import type { RdfDataset, RdfFormat, RdfQuad, SolidSidecarLogger } from '../types';
import { ValidationError } from '../types';
import { nullLogger } from '../utils';

export interface RdfCodecConfig {
  defaultInputFormat?: RdfFormat;
  defaultOutputFormat?: RdfFormat;
  validate?: boolean;
  preserveWhitespace?: boolean;
  maxQuads?: number;
  logger?: SolidSidecarLogger;
}

interface ResolvedRdfCodecConfig {
  defaultInputFormat: RdfFormat;
  defaultOutputFormat: RdfFormat;
  validate: boolean;
  preserveWhitespace: boolean;
  maxQuads: number;
  logger: SolidSidecarLogger;
}

export const DEFAULT_RDF_CODEC_CONFIG = {
  defaultInputFormat: 'text/turtle',
  defaultOutputFormat: 'text/turtle',
  validate: true,
  preserveWhitespace: false,
  maxQuads: 100_000,
  logger: nullLogger,
} satisfies ResolvedRdfCodecConfig;

export const NAMESPACES = {
  RDF: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
  RDFS: 'http://www.w3.org/2000/01/rdf-schema#',
  FOAF: 'http://xmlns.com/foaf/0.1/',
  SOLID: 'http://www.w3.org/ns/solid/terms#',
  ACL: 'http://www.w3.org/ns/auth/acl#',
  ACP: 'http://www.w3.org/ns/solid/acp#',
  SAI: 'http://www.w3.org/ns/solid/sai#',
  DCTERMS: 'http://purl.org/dc/terms/',
  XSD: 'http://www.w3.org/2001/XMLSchema#',
  PIM: 'http://www.w3.org/ns/pim/space#',
  PREFS: 'http://www.w3.org/ns/pim/prefs#',
  LDP: 'http://www.w3.org/ns/ldp#',
} as const;

export const PREFIXES: Record<string, string> = {
  rdf: NAMESPACES.RDF,
  rdfs: NAMESPACES.RDFS,
  foaf: NAMESPACES.FOAF,
  solid: NAMESPACES.SOLID,
  acl: NAMESPACES.ACL,
  acp: NAMESPACES.ACP,
  sai: NAMESPACES.SAI,
  dcterms: NAMESPACES.DCTERMS,
  xsd: NAMESPACES.XSD,
  pim: NAMESPACES.PIM,
  prefs: NAMESPACES.PREFS,
  ldp: NAMESPACES.LDP,
};

export interface RdfLiteral {
  value: string;
  type?: string;
  language?: string;
}

export type RdfTerm = string | RdfLiteral;

const RDF_TYPE = `${NAMESPACES.RDF}type`;
const ABSOLUTE_IRI = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const BLANK_NODE = /^_:[A-Za-z][A-Za-z0-9._-]*$/u;
const PREFIXED_NAME = /^([A-Za-z][\w-]*|):([\w.-]*)$/u;

export class RdfCodec {
  private readonly config: ResolvedRdfCodecConfig;
  private readonly customPrefixes = new Map<string, string>();
  private blankNodeCounter = 0;

  public constructor(config: RdfCodecConfig = {}) {
    this.config = {
      defaultInputFormat: config.defaultInputFormat ?? DEFAULT_RDF_CODEC_CONFIG.defaultInputFormat,
      defaultOutputFormat: config.defaultOutputFormat ?? DEFAULT_RDF_CODEC_CONFIG.defaultOutputFormat,
      validate: config.validate ?? DEFAULT_RDF_CODEC_CONFIG.validate,
      preserveWhitespace: config.preserveWhitespace ?? DEFAULT_RDF_CODEC_CONFIG.preserveWhitespace,
      maxQuads: config.maxQuads ?? DEFAULT_RDF_CODEC_CONFIG.maxQuads,
      logger: config.logger ?? DEFAULT_RDF_CODEC_CONFIG.logger,
    };

    if (!Number.isInteger(this.config.maxQuads) || this.config.maxQuads < 1) {
      throw new ValidationError('maxQuads must be a positive integer', 'maxQuads');
    }
  }

  public parse(input: string, format?: RdfFormat): RdfDataset {
    if (typeof input !== 'string') throw new ValidationError('RDF input must be a string', 'input');
    const actualFormat = format ?? this.config.defaultInputFormat;
    let quads: RdfQuad[];

    switch (actualFormat) {
      case 'text/turtle':
        quads = this.parseTurtle(input, false);
        break;
      case 'application/n-triples':
        quads = this.parseTurtle(input, true);
        break;
      case 'application/ld+json':
        quads = this.parseExpandedJsonLd(input);
        break;
      case 'application/rdf+xml':
        throw new ValidationError('RDF/XML is not supported by the portable TypeScript codec', 'format');
      default:
        throw new ValidationError(`Unsupported RDF format: ${String(actualFormat)}`, 'format');
    }

    if (this.config.validate) this.validateQuads(quads);
    return { quads, formats: [actualFormat] };
  }

  public parseCanonical(input: string, format?: RdfFormat): string {
    const dataset = this.parse(input, format);
    return this.serialize(dataset, 'application/n-triples');
  }

  public serialize(dataset: RdfDataset, format?: RdfFormat): string {
    this.validateDataset(dataset);
    const actualFormat = format ?? this.config.defaultOutputFormat;
    const sorted = [...dataset.quads].sort((a, b) => this.quadLine(a).localeCompare(this.quadLine(b)));

    switch (actualFormat) {
      case 'application/n-triples':
        if (sorted.some(quad => quad.graph !== undefined)) {
          throw new ValidationError('N-Triples cannot serialize named graphs', 'dataset');
        }
        return sorted.map(quad => this.quadLine(quad)).join('\n') + (sorted.length ? '\n' : '');
      case 'text/turtle':
        return sorted.map(quad => this.quadLine(quad)).join('\n') + (sorted.length ? '\n' : '');
      case 'application/ld+json':
        return this.serializeExpandedJsonLd(sorted);
      case 'application/rdf+xml':
        throw new ValidationError('RDF/XML is not supported by the portable TypeScript codec', 'format');
      default:
        throw new ValidationError(`Unsupported RDF format: ${String(actualFormat)}`, 'format');
    }
  }

  public addPrefix(prefix: string, uri: string): void {
    if (!/^(?:[A-Za-z][\w-]*)?$/u.test(prefix)) {
      throw new ValidationError('Invalid RDF prefix', 'prefix');
    }
    this.customPrefixes.set(prefix, this.requireAbsoluteIri(uri, 'uri'));
  }

  public removePrefix(prefix: string): void {
    this.customPrefixes.delete(prefix);
  }

  public expandPrefixedName(value: string): string {
    if (ABSOLUTE_IRI.test(value)) return value;
    const match = value.match(PREFIXED_NAME);
    if (!match) return value;
    const namespace = this.customPrefixes.get(match[1] ?? '') ?? PREFIXES[match[1] ?? ''];
    return namespace ? `${namespace}${match[2] ?? ''}` : value;
  }

  public createBlankNodeId(): string {
    this.blankNodeCounter += 1;
    return `_:b${this.blankNodeCounter}`;
  }

  public createTypedLiteral(value: string, type: string): RdfLiteral {
    return { value, type: this.requireAbsoluteIri(type, 'type') };
  }

  public createLanguageLiteral(value: string, language: string): RdfLiteral {
    if (!/^[A-Za-z]+(?:-[A-Za-z0-9]+)*$/u.test(language)) {
      throw new ValidationError('Invalid language tag', 'language');
    }
    return { value, language: language.toLowerCase() };
  }

  public isBlankNode(term: string): boolean {
    return BLANK_NODE.test(term);
  }

  public isLiteral(term: RdfTerm): term is RdfLiteral {
    return typeof term === 'object' && term !== null;
  }

  public isUri(term: RdfTerm): boolean {
    return typeof term === 'string' && ABSOLUTE_IRI.test(term);
  }

  public getConfig(): Readonly<ResolvedRdfCodecConfig> {
    return { ...this.config };
  }

  public getPrefixes(): Record<string, string> {
    return { ...PREFIXES, ...Object.fromEntries(this.customPrefixes) };
  }

  private parseTurtle(input: string, nTriplesOnly: boolean): RdfQuad[] {
    const prefixes = new Map<string, string>([
      ...Object.entries(PREFIXES),
      ...this.customPrefixes.entries(),
    ]);
    let base: string | undefined;
    let body = '';

    for (const line of input.split(/\r?\n/u)) {
      const clean = this.stripComment(line).trim();
      if (!clean) continue;
      const prefix = clean.match(/^(?:@prefix|PREFIX)\s+([A-Za-z][\w-]*|):\s*<([^>]*)>\s*\.?$/iu);
      if (prefix) {
        if (nTriplesOnly) throw new ValidationError('N-Triples does not allow prefix directives', 'input');
        prefixes.set(prefix[1] === ':' ? '' : prefix[1] ?? '', this.resolveIri(prefix[2] ?? '', base));
        continue;
      }
      const baseMatch = clean.match(/^(?:@base|BASE)\s+<([^>]*)>\s*\.?$/iu);
      if (baseMatch) {
        if (nTriplesOnly) throw new ValidationError('N-Triples does not allow base directives', 'input');
        base = this.requireAbsoluteIri(baseMatch[1] ?? '', 'input');
        continue;
      }
      body += `${clean}\n`;
    }

    const quads: RdfQuad[] = [];
    for (const statement of this.splitTopLevel(body, '.')) {
      const trimmed = statement.trim();
      if (!trimmed) continue;
      const firstSpace = this.findWhitespace(trimmed, 0);
      if (firstSpace < 0) throw new ValidationError('RDF statement is missing a predicate and object', 'input');
      const subjectToken = trimmed.slice(0, firstSpace);
      const rest = trimmed.slice(firstSpace).trim();
      const subject = this.parseResourceTerm(subjectToken, prefixes, base, nTriplesOnly, 'subject');

      for (const predicateObject of this.splitTopLevel(rest, ';')) {
        const pair = predicateObject.trim();
        if (!pair) continue;
        const predicateSpace = this.findWhitespace(pair, 0);
        if (predicateSpace < 0) throw new ValidationError('RDF predicate is missing an object', 'input');
        const predicateToken = pair.slice(0, predicateSpace);
        const objectList = pair.slice(predicateSpace).trim();
        const predicate = predicateToken === 'a'
          ? RDF_TYPE
          : this.parseResourceTerm(predicateToken, prefixes, base, nTriplesOnly, 'predicate');

        for (const objectToken of this.splitTopLevel(objectList, ',')) {
          const object = this.parseObjectTerm(objectToken.trim(), prefixes, base, nTriplesOnly);
          this.pushQuad(quads, { subject, predicate, object });
        }
      }
    }
    return quads;
  }

  private parseExpandedJsonLd(input: string): RdfQuad[] {
    let parsed: unknown;
    try {
      parsed = JSON.parse(input) as unknown;
    } catch {
      throw new ValidationError('Invalid JSON-LD JSON document', 'input');
    }
    const nodes = Array.isArray(parsed) ? parsed : [parsed];
    const quads: RdfQuad[] = [];
    for (const value of nodes) {
      if (!this.isRecord(value)) throw new ValidationError('JSON-LD nodes must be objects', 'input');
      const subject = value['@id'];
      if (typeof subject !== 'string' || (!ABSOLUTE_IRI.test(subject) && !BLANK_NODE.test(subject))) {
        throw new ValidationError('JSON-LD nodes require an absolute or blank-node @id', 'input');
      }
      for (const [predicate, rawValues] of Object.entries(value)) {
        if (predicate === '@id' || predicate === '@context') continue;
        if (predicate === '@type') {
          for (const type of this.asArray(rawValues)) {
            if (typeof type !== 'string') throw new ValidationError('JSON-LD @type values must be strings', 'input');
            this.pushQuad(quads, { subject, predicate: RDF_TYPE, object: this.requireAbsoluteIri(type, 'input') });
          }
          continue;
        }
        const expandedPredicate = this.requireAbsoluteIri(this.expandPrefixedName(predicate), 'input');
        for (const raw of this.asArray(rawValues)) {
          this.pushQuad(quads, { subject, predicate: expandedPredicate, object: this.jsonLdObject(raw) });
        }
      }
    }
    return quads;
  }

  private jsonLdObject(value: unknown): string {
    if (this.isRecord(value) && typeof value['@id'] === 'string') {
      const id = value['@id'];
      if (!ABSOLUTE_IRI.test(id) && !BLANK_NODE.test(id)) throw new ValidationError('Invalid JSON-LD @id value', 'input');
      return id;
    }
    if (this.isRecord(value) && value['@value'] !== undefined) {
      const raw = value['@value'];
      if (!['string', 'number', 'boolean'].includes(typeof raw)) throw new ValidationError('Invalid JSON-LD literal value', 'input');
      const language = value['@language'];
      const type = value['@type'];
      if (language !== undefined && typeof language !== 'string') throw new ValidationError('Invalid JSON-LD language', 'input');
      if (type !== undefined && typeof type !== 'string') throw new ValidationError('Invalid JSON-LD datatype', 'input');
      return this.literalToken(String(raw), language, type);
    }
    if (typeof value === 'string') return this.literalToken(value);
    if (typeof value === 'number') return this.literalToken(String(value), undefined, `${NAMESPACES.XSD}decimal`);
    if (typeof value === 'boolean') return this.literalToken(String(value), undefined, `${NAMESPACES.XSD}boolean`);
    throw new ValidationError('Unsupported JSON-LD value shape', 'input');
  }

  private serializeExpandedJsonLd(quads: RdfQuad[]): string {
    if (quads.some(quad => quad.graph !== undefined)) {
      throw new ValidationError('JSON-LD graph serialization is not supported by this codec', 'dataset');
    }
    const nodes = new Map<string, Record<string, unknown>>();
    for (const quad of quads) {
      const node = nodes.get(quad.subject) ?? { '@id': quad.subject };
      const key = quad.predicate === RDF_TYPE ? '@type' : quad.predicate;
      const value = quad.predicate === RDF_TYPE ? quad.object : this.objectToJsonLd(quad.object);
      const existing = node[key];
      node[key] = existing === undefined ? [value] : [...this.asArray(existing), value];
      nodes.set(quad.subject, node);
    }
    return `${JSON.stringify([...nodes.values()], null, 2)}\n`;
  }

  private objectToJsonLd(object: string): unknown {
    if (ABSOLUTE_IRI.test(object) || BLANK_NODE.test(object)) return { '@id': object };
    const literal = object.match(/^"((?:\\.|[^"\\])*)"(?:@([A-Za-z]+(?:-[A-Za-z0-9]+)*)|\^\^<([^>]+)>)?$/u);
    if (!literal) throw new ValidationError('Dataset contains an invalid object term', 'dataset');
    const result: Record<string, unknown> = { '@value': JSON.parse(`"${literal[1] ?? ''}"`) };
    if (literal[2]) result['@language'] = literal[2];
    if (literal[3]) result['@type'] = literal[3];
    return result;
  }

  private parseResourceTerm(
    token: string,
    prefixes: Map<string, string>,
    base: string | undefined,
    nTriplesOnly: boolean,
    field: string
  ): string {
    if (BLANK_NODE.test(token)) return token;
    if (token.startsWith('<') && token.endsWith('>')) return this.resolveIri(token.slice(1, -1), base);
    if (!nTriplesOnly) {
      const prefixed = token.match(PREFIXED_NAME);
      if (prefixed) {
        const namespace = prefixes.get(prefixed[1] ?? '');
        if (!namespace) throw new ValidationError(`Unknown RDF prefix: ${prefixed[1] ?? ''}`, 'input');
        return `${namespace}${prefixed[2] ?? ''}`;
      }
    }
    throw new ValidationError(`Invalid RDF ${field} term`, 'input');
  }

  private parseObjectTerm(
    token: string,
    prefixes: Map<string, string>,
    base: string | undefined,
    nTriplesOnly: boolean
  ): string {
    if (!token) throw new ValidationError('RDF object must not be empty', 'input');
    if (token.startsWith('"')) return this.parseLiteral(token, prefixes, base, nTriplesOnly);
    return this.parseResourceTerm(token, prefixes, base, nTriplesOnly, 'object');
  }

  private parseLiteral(
    token: string,
    prefixes: Map<string, string>,
    base: string | undefined,
    nTriplesOnly: boolean
  ): string {
    let escaped = false;
    let end = -1;
    for (let index = 1; index < token.length; index += 1) {
      const char = token[index];
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') { end = index; break; }
    }
    if (end < 0) throw new ValidationError('Unterminated RDF literal', 'input');
    const lexical = token.slice(1, end);
    const suffix = token.slice(end + 1).trim();
    if (!suffix) return `"${lexical}"`;
    if (/^@[A-Za-z]+(?:-[A-Za-z0-9]+)*$/u.test(suffix)) return `"${lexical}"${suffix.toLowerCase()}`;
    if (suffix.startsWith('^^')) {
      const datatype = this.parseResourceTerm(suffix.slice(2), prefixes, base, nTriplesOnly, 'datatype');
      return `"${lexical}"^^<${datatype}>`;
    }
    throw new ValidationError('Invalid RDF literal suffix', 'input');
  }

  private stripComment(line: string): string {
    let inString = false;
    let inIri = false;
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
      const char = line[index];
      if (escaped) { escaped = false; continue; }
      if (inString && char === '\\') { escaped = true; continue; }
      if (!inIri && char === '"') inString = !inString;
      else if (!inString && char === '<') inIri = true;
      else if (!inString && char === '>') inIri = false;
      else if (!inString && !inIri && char === '#') return line.slice(0, index);
    }
    return line;
  }

  private splitTopLevel(value: string, delimiter: string): string[] {
    const result: string[] = [];
    let start = 0;
    let inString = false;
    let inIri = false;
    let escaped = false;
    for (let index = 0; index < value.length; index += 1) {
      const char = value[index];
      if (escaped) { escaped = false; continue; }
      if (inString && char === '\\') { escaped = true; continue; }
      if (!inIri && char === '"') inString = !inString;
      else if (!inString && char === '<') inIri = true;
      else if (!inString && char === '>') inIri = false;
      else if (!inString && !inIri && char === delimiter && this.isDelimiterToken(value, index, delimiter)) {
        result.push(value.slice(start, index));
        start = index + 1;
      }
    }
    if (inString || inIri) throw new ValidationError('Unterminated RDF string or IRI', 'input');
    result.push(value.slice(start));
    return result;
  }

  private isDelimiterToken(value: string, index: number, delimiter: string): boolean {
    if (delimiter !== '.') return true;
    const before = index === 0 ? '' : value[index - 1] ?? '';
    const after = value[index + 1] ?? '';
    return /\s/u.test(before) && (after === '' || /\s/u.test(after));
  }

  private findWhitespace(value: string, start: number): number {
    let inString = false;
    let inIri = false;
    let escaped = false;
    for (let index = start; index < value.length; index += 1) {
      const char = value[index];
      if (escaped) { escaped = false; continue; }
      if (inString && char === '\\') { escaped = true; continue; }
      if (!inIri && char === '"') inString = !inString;
      else if (!inString && char === '<') inIri = true;
      else if (!inString && char === '>') inIri = false;
      else if (!inString && !inIri && /\s/u.test(char ?? '')) return index;
    }
    return -1;
  }

  private resolveIri(value: string, base?: string): string {
    try {
      if (ABSOLUTE_IRI.test(value)) return new URL(value).toString();
      if (!base) throw new Error('relative IRI without base');
      return new URL(value, base).toString();
    } catch {
      throw new ValidationError('Invalid or unresolved RDF IRI', 'input');
    }
  }

  private requireAbsoluteIri(value: string, field: string): string {
    if (!ABSOLUTE_IRI.test(value)) throw new ValidationError('IRI must be absolute', field);
    try { return new URL(value).toString(); }
    catch { throw new ValidationError('IRI must be a valid absolute URL', field); }
  }

  private literalToken(value: string, language?: unknown, type?: unknown): string {
    const escaped = JSON.stringify(value);
    if (typeof language === 'string') {
      if (!/^[A-Za-z]+(?:-[A-Za-z0-9]+)*$/u.test(language)) throw new ValidationError('Invalid language tag', 'input');
      return `${escaped}@${language.toLowerCase()}`;
    }
    if (typeof type === 'string') return `${escaped}^^<${this.requireAbsoluteIri(type, 'input')}>`;
    return escaped;
  }

  private pushQuad(quads: RdfQuad[], quad: RdfQuad): void {
    if (quads.length >= this.config.maxQuads) {
      throw new ValidationError(`Exceeded maximum quad count: ${this.config.maxQuads}`, 'input');
    }
    quads.push(quad);
  }

  private validateDataset(dataset: RdfDataset): void {
    if (!dataset || !Array.isArray(dataset.quads)) throw new ValidationError('Invalid RDF dataset', 'dataset');
    if (dataset.quads.length > this.config.maxQuads) throw new ValidationError('Dataset exceeds maximum quad count', 'dataset');
    if (this.config.validate) this.validateQuads(dataset.quads);
  }

  private validateQuads(quads: RdfQuad[]): void {
    for (const quad of quads) {
      if (!quad.subject || !quad.predicate || !quad.object) throw new ValidationError('RDF quad terms must not be empty', 'dataset');
      if (!ABSOLUTE_IRI.test(quad.predicate)) throw new ValidationError('RDF predicates must be absolute IRIs', 'dataset');
      if (!ABSOLUTE_IRI.test(quad.subject) && !BLANK_NODE.test(quad.subject)) throw new ValidationError('Invalid RDF subject', 'dataset');
      if (!ABSOLUTE_IRI.test(quad.object) && !BLANK_NODE.test(quad.object) && !quad.object.startsWith('"')) {
        throw new ValidationError('Invalid RDF object', 'dataset');
      }
    }
  }

  private quadLine(quad: RdfQuad): string {
    const subject = this.formatResource(quad.subject);
    const predicate = this.formatResource(quad.predicate);
    const object = quad.object.startsWith('"') ? quad.object : this.formatResource(quad.object);
    if (quad.graph) return `${subject} ${predicate} ${object} ${this.formatResource(quad.graph)} .`;
    return `${subject} ${predicate} ${object} .`;
  }

  private formatResource(value: string): string {
    return BLANK_NODE.test(value) ? value : `<${value}>`;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private asArray(value: unknown): unknown[] {
    return Array.isArray(value) ? value : [value];
  }
}

export default RdfCodec;
