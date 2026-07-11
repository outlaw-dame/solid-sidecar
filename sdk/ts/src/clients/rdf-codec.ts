/**
 * Solid Sidecar TypeScript SDK - RDF Codec
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the RDF Codec for parsing and serializing RDF data.
 * Implements a portable client-facing codec for Solid clients.
 *
 * Security Level: HIGH - Handles data serialization/deserialization
 */

import type { RdfFormat, RdfDataset, RdfQuad, SolidSidecarLogger } from '../types';
import { ValidationError } from '../types';

// ============================================================================
// RDF Codec Configuration
// ============================================================================

/**
 * Configuration for RDF Codec
 */
export interface RdfCodecConfig {
  /** Default input format when not specified */
  defaultInputFormat?: RdfFormat;
  
  /** Default output format when not specified */
  defaultOutputFormat?: RdfFormat;
  
  /** Whether to validate RDF during parsing */
  validate?: boolean;
  
  /** Whether to preserve whitespace in literals */
  preserveWhitespace?: boolean;
  
  /** Maximum number of quads to parse (prevents DoS) */
  maxQuads?: number;
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default RDF Codec configuration
 */
export const DEFAULT_RDF_CODEC_CONFIG: Required<RdfCodecConfig> = {
  defaultInputFormat: 'text/turtle',
  defaultOutputFormat: 'text/turtle',
  validate: true,
  preserveWhitespace: false,
  maxQuads: 100000, // 100k quads max to prevent memory exhaustion
  logger: console,
};

// ============================================================================
// RDF Namespaces
// ============================================================================

/** Common RDF namespaces */
export const NAMESPACES = {
  // RDF
  RDF: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
  RDFS: 'http://www.w3.org/2000/01/rdf-schema#',
  
  // FOAF
  FOAF: 'http://xmlns.com/foaf/0.1/',
  
  // Solid
  SOLID: 'http://www.w3.org/ns/solid/terms#',
  
  // ACL (WAC)
  ACL: 'http://www.w3.org/ns/auth/acl#',
  
  // ACP
  ACP: 'http://www.w3.org/ns/solid/acp#',
  
  // SAI
  SAI: 'http://www.w3.org/ns/solid/sai#',
  
  // DCTERMS
  DCTERMS: 'http://purl.org/dc/terms/',
  
  // XSD
  XSD: 'http://www.w3.org/2001/XMLSchema#',
  
  // PIM
  PIM: 'http://www.w3.org/ns/pim/space#',
  PREFS: 'http://www.w3.org/ns/pim/prefs#',
  
  // LDP
  LDP: 'http://www.w3.org/ns/ldp#',
} as const;

/** Namespace prefix mappings */
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

// ============================================================================
// Literal Types
// ============================================================================

/** RDF literal value */
export interface RdfLiteral {
  value: string;
  type?: string;
  language?: string;
}

/** RDF term (subject, predicate, object, or graph) */
export type RdfTerm = string | RdfLiteral;

// ============================================================================
// RDF Codec Class
// ============================================================================

/**
 * RDF Codec for Solid Sidecar
 * 
 * Features:
 * - Parse RDF from multiple formats (Turtle, JSON-LD, N-Triples)
 * - Serialize RDF to multiple formats
 * - Canonicalize RDF for comparison
 * - Validate RDF structure
 * - Namespace prefix handling
 * - Security limits (max quads, etc.)
 * - Error handling with detailed messages
 */
export class RdfCodec {
  private readonly config: Required<RdfCodecConfig>;
  private readonly logger: SolidSidecarLogger;
  private readonly customPrefixes: Map<string, string> = new Map();
  
  constructor(config: RdfCodecConfig = {}) {
    this.config = {
      ...DEFAULT_RDF_CODEC_CONFIG,
      ...config,
    };
    this.logger = this.config.logger;
    
    this.logger.debug('RdfCodec initialized', {
      defaultInputFormat: this.config.defaultInputFormat,
      defaultOutputFormat: this.config.defaultOutputFormat,
      maxQuads: this.config.maxQuads,
    });
  }

  // ==========================================================================
  // Parsing Methods
  // ==========================================================================

  /**
   * Parses RDF from a string
   * 
   * @param input - The RDF string to parse
   * @param format - The format of the input (defaults to config)
   * @returns The parsed RDF dataset
   */
  public parse(input: string, format?: RdfFormat): RdfDataset {
    const actualFormat = format || this.config.defaultInputFormat;
    
    this.logger.debug('Parsing RDF', {
      format: actualFormat,
      inputLength: input.length,
    });
    
    let quads: RdfQuad[];
    
    switch (actualFormat) {
      case 'text/turtle':
      case 'application/n-triples':
        quads = this.parseTurtleOrNTriples(input, actualFormat);
        break;
      case 'application/ld+json':
        quads = this.parseJsonLd(input);
        break;
      case 'application/rdf+xml':
        quads = this.parseRdfXml(input);
        break;
      default:
        throw new ValidationError(
          `Unsupported RDF format: ${actualFormat}`,
          'format'
        );
    }
    
    // Validate quad count
    if (quads.length > this.config.maxQuads) {
      throw new ValidationError(
        `Exceeded maximum quad count: ${quads.length} > ${this.config.maxQuads}`,
        'input'
      );
    }
    
    // Validate quads
    if (this.config.validate) {
      this.validateQuads(quads);
    }
    
    return {
      quads,
      formats: [actualFormat],
    };
  }

  /**
   * Parses RDF and canonicalizes it
   * 
   * @param input - The RDF string to parse
   * @param format - The format of the input
   * @returns Canonicalized RDF string
   */
  public parseCanonical(input: string, format?: RdfFormat): string {
    const dataset = this.parse(input, format);
    return this.serialize(dataset, 'application/n-triples');
  }

  // ==========================================================================
  // Serialization Methods
  // ==========================================================================

  /**
   * Serializes an RDF dataset to a string
   * 
   * @param dataset - The RDF dataset to serialize
   * @param format - The output format (defaults to config)
   * @returns The serialized RDF string
   */
  public serialize(dataset: RdfDataset, format?: RdfFormat): string {
    const actualFormat = format || this.config.defaultOutputFormat;
    
    this.logger.debug('Serializing RDF', {
      format: actualFormat,
      quadCount: dataset.quads.length,
    });
    
    let output: string;
    
    switch (actualFormat) {
      case 'text/turtle':
        output = this.serializeTurtle(dataset);
        break;
      case 'application/n-triples':
        output = this.serializeNTriples(dataset);
        break;
      case 'application/ld+json':
        output = this.serializeJsonLd(dataset);
        break;
      case 'application/rdf+xml':
        output = this.serializeRdfXml(dataset);
        break;
      default:
        throw new ValidationError(
          `Unsupported RDF format: ${actualFormat}`,
          'format'
        );
    }
    
    return output;
  }

  // ==========================================================================
  // Utility Methods
  // ==========================================================================

  /**
   * Adds a custom namespace prefix
   * 
   * @param prefix - The prefix (e.g., 'ex')
   * @param uri - The namespace URI
   */
  public addPrefix(prefix: string, uri: string): void {
    this.customPrefixes.set(prefix, uri);
    this.logger.debug('Added custom prefix', { prefix, uri });
  }

  /**
   * Removes a custom namespace prefix
   * 
   * @param prefix - The prefix to remove
   */
  public removePrefix(prefix: string): void {
    this.customPrefixes.delete(prefix);
    this.logger.debug('Removed custom prefix', { prefix });
  }

  /**
   * Expands a prefixed name to a full URI
   * 
   * @param prefixedName - The prefixed name (e.g., 'foaf:name')
   * @returns The expanded URI
   */
  public expandPrefixedName(prefixedName: string): string {
    // Check if it's already a full URI
    if (/^https?:\/\//i.test(prefixedName)) {
      return prefixedName;
    }
    
    // Split prefix and local name
    const colonIndex = prefixedName.indexOf(':');
    if (colonIndex === -1) {
      return prefixedName; // No prefix, return as-is
    }
    
    const prefix = prefixedName.substring(0, colonIndex);
    const localName = prefixedName.substring(colonIndex + 1);
    
    // Check custom prefixes first
    const customUri = this.customPrefixes.get(prefix);
    if (customUri) {
      return customUri + localName;
    }
    
    // Check built-in prefixes
    const builtinUri = PREFIXES[prefix];
    if (builtinUri) {
      return builtinUri + localName;
    }
    
    // Unknown prefix, return as-is
    return prefixedName;
  }

  /**
   * Creates a blank node ID
   * 
   * @returns A unique blank node ID
   */
  public createBlankNodeId(): string {
    // Generate a unique identifier for blank nodes
    // In a real implementation, this would need to track used IDs
    return `_:b${Date.now()}${Math.random().toString(36).substring(2)}`;
  }

  /**
   * Creates a literal with type
   * 
   * @param value - The literal value
   * @param type - The datatype URI
   * @returns The literal
   */
  public createTypedLiteral(value: string, type: string): RdfLiteral {
    return { value, type };
  }

  /**
   * Creates a literal with language tag
   * 
   * @param value - The literal value
   * @param language - The language tag
   * @returns The literal
   */
  public createLanguageLiteral(value: string, language: string): RdfLiteral {
    return { value, language };
  }

  /**
   * Checks if a term is a blank node
   * 
   * @param term - The term to check
   * @returns true if it's a blank node
   */
  public isBlankNode(term: string): boolean {
    return term.startsWith('_:') || term.startsWith('?') || term.startsWith('$');
  }

  /**
   * Checks if a term is a literal
   * 
   * @param term - The term to check
   * @returns true if it's a literal
   */
  public isLiteral(term: RdfTerm): term is RdfLiteral {
    return typeof term !== 'string' && term !== null && term !== undefined;
  }

  /**
   * Checks if a term is a URI
   * 
   * @param term - The term to check
   * @returns true if it's a URI
   */
  public isUri(term: RdfTerm): boolean {
    return typeof term === 'string' && !this.isBlankNode(term);
  }

  // ==========================================================================
  // Getters
  // ==========================================================================

  /**
   * Gets the configuration
   */
  public getConfig(): Required<RdfCodecConfig> {
    return { ...this.config };
  }

  /**
   * Gets all registered prefixes
   */
  public getPrefixes(): Record<string, string> {
    const prefixes: Record<string, string> = { ...PREFIXES };
    for (const [prefix, uri] of this.customPrefixes) {
      prefixes[prefix] = uri;
    }
    return prefixes;
  }

  // ==========================================================================
  // Private Parsing Methods
  // ==========================================================================

  /**
   * Parses Turtle or N-Triples format
   */
  private parseTurtleOrNTriples(input: string, format: RdfFormat): RdfQuad[] {
    const quads: RdfQuad[] = [];
    const lines = input.split('\n');
    
    let currentGraph: string | undefined;
    let currentSubject: string | undefined;
    let currentPredicate: string | undefined;
    
    // Regex patterns
    const blankNodePattern = /^_(:[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+)$/;
    const uriPattern = /^<([^>]+)>$/;
    const literalPattern = /^"([^"]*)"(?:@([a-zA-Z-]+)|\^\^<([^>]+)>)?$/;
    const prefixPattern = /^@prefix\s+([a-zA-Z0-9_-]+)\s*:\s*<([^>]+)>\s*\./;
    const basePattern = /^@base\s+<([^>]+)>\s*\./;
    const graphStartPattern = /^\{/;
    const graphEndPattern = /^\}/;
    
    const localPrefixes: Map<string, string> = new Map();
    let baseUri = '';
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      // Handle prefixes
      const prefixMatch = trimmed.match(prefixPattern);
      if (prefixMatch) {
        localPrefixes.set(prefixMatch[1], prefixMatch[2]);
        continue;
      }
      
      // Handle base
      const baseMatch = trimmed.match(basePattern);
      if (baseMatch) {
        baseUri = baseMatch[1];
        continue;
      }
      
      // Handle graph start
      if (graphStartPattern.test(trimmed)) {
        // For simplicity, we're not handling named graphs in this basic implementation
        continue;
      }
      
      // Handle graph end
      if (graphEndPattern.test(trimmed)) {
        currentGraph = undefined;
        continue;
      }
      
      // Handle statements
      const statementMatch = trimmed.match(/^([^\s]+)\s+([^\s]+)\s+(.+)\s*\.$/);
      if (statementMatch) {
        const subject = this.parseTerm(statementMatch[1], localPrefixes, baseUri);
        const predicate = this.parseTerm(statementMatch[2], localPrefixes, baseUri);
        const object = this.parseTerm(statementMatch[3], localPrefixes, baseUri);
        
        if (subject && predicate) {
          quads.push({
            subject: subject.value,
            predicate: predicate.value,
            object: typeof object === 'string' ? object : object.value,
            graph: currentGraph,
          });
        }
        continue;
      }
      
      // Handle subject-predicate objects with semicolons
      const semiMatch = trimmed.match(/^([^\s]+)\s+([^\s]+)\s+([^;]+);$/);
      if (semiMatch) {
        currentSubject = this.parseTerm(semiMatch[1], localPrefixes, baseUri).value;
        currentPredicate = this.parseTerm(semiMatch[2], localPrefixes, baseUri).value;
        const object = this.parseTerm(semiMatch[3], localPrefixes, baseUri);
        
        if (currentSubject && currentPredicate) {
          quads.push({
            subject: currentSubject,
            predicate: currentPredicate,
            object: typeof object === 'string' ? object : object.value,
            graph: currentGraph,
          });
        }
        continue;
      }
      
      // Handle predicate-object pairs with semicolons
      if (currentSubject && trimmed.endsWith(';')) {
        const parts = trimmed.split(/\s+/);
        if (parts.length >= 2) {
          currentPredicate = this.parseTerm(parts[0], localPrefixes, baseUri).value;
          const object = this.parseTerm(parts.slice(1, -1).join(' '), localPrefixes, baseUri);
          
          if (currentPredicate) {
            quads.push({
              subject: currentSubject,
              predicate: currentPredicate,
              object: typeof object === 'string' ? object : object.value,
              graph: currentGraph,
            });
          }
        }
        continue;
      }
      
      // Handle object lists with commas
      if (currentSubject && currentPredicate) {
        const parts = trimmed.split(',').map(p => p.trim()).filter(p => p && !p.endsWith('.'));
        for (const part of parts) {
          const object = this.parseTerm(part, localPrefixes, baseUri);
          quads.push({
            subject: currentSubject,
            predicate: currentPredicate,
            object: typeof object === 'string' ? object : object.value,
            graph: currentGraph,
          });
        }
      }
    }
    
    return quads;
  }

  /**
   * Parses JSON-LD format
   */
  private parseJsonLd(input: string): RdfQuad[] {
    const quads: RdfQuad[] = [];
    
    try {
      const data = JSON.parse(input);
      
      // Simple JSON-LD to quads conversion
      // In production, use a proper JSON-LD processor
      if (Array.isArray(data)) {
        // It's a list of statements
        for (const stmt of data) {
          if (stmt['@id'] && stmt['@type'] && stmt['@value']) {
            // Literal
            quads.push({
              subject: '',
              predicate: '',
              object: JSON.stringify(stmt),
            });
          }
        }
      } else if (data['@graph']) {
        // JSON-LD with @graph
        const graph = data['@graph'];
        if (Array.isArray(graph)) {
          for (const item of graph) {
            // Convert each item to quads
            this.jsonLdItemToQuads(item, quads);
          }
        }
      } else {
        // Single object
        this.jsonLdItemToQuads(data, quads);
      }
    } catch (error) {
      throw new ValidationError(
        `Failed to parse JSON-LD: ${error instanceof Error ? error.message : String(error)}`,
        'input'
      );
    }
    
    return quads;
  }

  /**
   * Converts a JSON-LD item to quads
   */
  private jsonLdItemToQuads(item: unknown, quads: RdfQuad[]): void {
    if (typeof item !== 'object' || item === null) return;
    
    const obj = item as Record<string, unknown>;
    const subject = obj['@id'] as string || this.createBlankNodeId();
    
    // Handle types
    const types = obj['@type'];
    if (types) {
      const typeArray = Array.isArray(types) ? types : [types];
      for (const type of typeArray) {
        if (typeof type === 'string') {
          quads.push({
            subject,
            predicate: NAMESPACES.RDF + 'type',
            object: type,
          });
        }
      }
    }
    
    // Handle other properties
    for (const [key, value] of Object.entries(obj)) {
      if (key.startsWith('@')) continue; // Skip JSON-LD keywords
      
      const predicate = this.expandPrefixedName(key);
      
      if (value === null || value === undefined) continue;
      
      if (Array.isArray(value)) {
        for (const v of value) {
          this.jsonLdValueToQuad(subject, predicate, v, quads);
        }
      } else {
        this.jsonLdValueToQuad(subject, predicate, value, quads);
      }
    }
  }

  /**
   * Converts a JSON-LD value to a quad
   */
  private jsonLdValueToQuad(
    subject: string,
    predicate: string,
    value: unknown,
    quads: RdfQuad[]
  ): void {
    if (typeof value === 'string') {
      // Check if it's a reference to another resource
      if (value.startsWith('http://') || value.startsWith('https://') || this.isBlankNode(value)) {
        quads.push({ subject, predicate, object: value });
      } else {
        // It's a literal
        quads.push({ subject, predicate, object: `"${value}"` });
      }
    } else if (typeof value === 'object' && value !== null) {
      const obj = value as Record<string, unknown>;
      
      if ('@id' in obj) {
        // It's a reference
        quads.push({ subject, predicate, object: obj['@id'] as string });
      } else if ('@value' in obj) {
        // It's a literal
        const literalValue = obj['@value'] as string;
        const literalType = obj['@type'] as string || undefined;
        const literalLanguage = obj['@language'] as string || undefined;
        
        const literal: RdfLiteral = { value: literalValue };
        if (literalType) literal.type = literalType;
        if (literalLanguage) literal.language = literalLanguage;
        
        quads.push({ 
          subject, 
          predicate, 
          object: JSON.stringify(literal)
        });
      }
    } else if (typeof value === 'boolean' || typeof value === 'number') {
      // JSON native types
      quads.push({ 
        subject, 
        predicate, 
        object: `"${value}"`,
        graph: `http://www.w3.org/2001/XMLSchema#${typeof value === 'number' ? 'decimal' : 'boolean'}`
      });
    }
  }

  /**
   * Parses RDF/XML format (simplified)
   */
  private parseRdfXml(input: string): RdfQuad[] {
    const quads: RdfQuad[] = [];
    
    // This is a simplified parser. In production, use a proper XML parser
    // and XSLT or a dedicated RDF/XML library.
    
    throw new ValidationError(
      'RDF/XML parsing not implemented. Use Turtle or JSON-LD.',
      'format'
    );
  }

  /**
   * Parses a term (subject, predicate, or object)
   */
  private parseTerm(
    term: string,
    prefixes: Map<string, string>,
    baseUri: string
  ): { value: string } | RdfLiteral {
    // Remove trailing punctuation
    term = term.replace(/[.,;\/]$/, '').trim();
    
    // Check for blank node
    if (blankNodePattern.test(term)) {
      return { value: term };
    }
    
    // Check for URI in angle brackets
    const uriMatch = term.match(uriPattern);
    if (uriMatch) {
      return { value: uriMatch[1] };
    }
    
    // Check for literal
    const literalMatch = term.match(literalPattern);
    if (literalMatch) {
      const value = literalMatch[1];
      const language = literalMatch[2];
      const type = literalMatch[3];
      
      const result: RdfLiteral = { value };
      if (language) result.language = language;
      if (type) result.type = type;
      
      return result;
    }
    
    // Check for prefixed name
    const colonIndex = term.indexOf(':');
    if (colonIndex > 0) {
      const prefix = term.substring(0, colonIndex);
      const localName = term.substring(colonIndex + 1);
      
      const uri = prefixes.get(prefix) || PREFIXES[prefix];
      if (uri) {
        return { value: uri + localName };
      }
    }
    
    // If it's a relative URI, resolve against base
    if (term.startsWith('/') || term.startsWith('./') || term.startsWith('../')) {
      try {
        const url = new URL(term, baseUri || 'http://example.org');
        return { value: url.toString() };
      } catch {
        return { value: term };
      }
    }
    
    // Default: return as-is
    return { value: term };
  }

  // ==========================================================================
  // Private Serialization Methods
  // ==========================================================================

  /**
   * Serializes to Turtle format
   */
  private serializeTurtle(dataset: RdfDataset): string {
    const lines: string[] = [];
    
    // Add prefixes
    lines.push('@prefix rdf: <' + NAMESPACES.RDF + '> .');
    lines.push('@prefix rdfs: <' + NAMESPACES.RDFS + '> .');
    lines.push('@prefix xsd: <' + NAMESPACES.XSD + '> .');
    lines.push('');
    
    // Group by subject
    const bySubject = new Map<string, RdfQuad[]>();
    for (const quad of dataset.quads) {
      const key = quad.graph ? `${quad.subject} [${quad.graph}]` : quad.subject;
      if (!bySubject.has(key)) {
        bySubject.set(key, []);
      }
      bySubject.get(key)?.push(quad);
    }
    
    // Serialize each subject group
    for (const [subject, quads] of bySubject) {
      const isGraph = subject.includes('[');
      const subjectUri = isGraph ? subject.split('[')[0].trim() : subject;
      
      if (isGraph) {
        const graphName = subject.match(/\[([^\]]+)\]/)?.[1];
        lines.push(`${subjectUri} {`);
        if (graphName) {
          lines.push(`  GRAPH <${graphName}> {`);
        }
        this.serializeQuadGroup(quads, lines, '  ');
        if (graphName) {
          lines.push(`  }`);
        }
        lines.push(`}`);
      } else {
        this.serializeQuadGroup(quads, lines, '');
      }
      lines.push('');
    }
    
    return lines.join('\n');
  }

  /**
   * Serializes a group of quads sharing the same subject
   */
  private serializeQuadGroup(quads: RdfQuad[], lines: string[], indent: string): void {
    if (quads.length === 0) return;
    
    const subject = quads[0].subject;
    
    // Write subject
    lines.push(`${indent}<${subject}>`);
    
    // Group by predicate
    const byPredicate = new Map<string, RdfQuad[]>();
    for (const quad of quads) {
      if (!byPredicate.has(quad.predicate)) {
        byPredicate.set(quad.predicate, []);
      }
      byPredicate.get(quad.predicate)?.push(quad);
    }
    
    // Serialize predicates
    let firstPredicate = true;
    for (const [predicate, predQuads] of byPredicate) {
      const line = predQuads.length > 1 || firstPredicate ? ' a' : ' ;';
      const shortForm = this.shortenUri(predicate);
      
      if (firstPredicate) {
        lines.push(`${indent}  ${shortForm}`);
        firstPredicate = false;
      } else {
        lines.push(`${indent}  ; ${shortForm}`);
      }
      
      // Serialize objects
      this.serializeObjects(predQuads, lines, indent, predicate);
    }
    
    lines.push(`${indent}  .`);
  }

  /**
   * Serializes object values
   */
  private serializeObjects(quads: RdfQuad[], lines: string[], indent: string, predicate: string): void {
    const objects = quads.map(q => q.object);
    
    for (let i = 0; i < objects.length; i++) {
      const obj = objects[i];
      
      if (obj.startsWith('_:') || obj.startsWith('?') || obj.startsWith('$')) {
        // Blank node
        lines.push(` ${obj}`);
      } else if (obj.startsWith('http://') || obj.startsWith('https://')) {
        // URI
        const shortForm = this.shortenUri(obj);
        lines.push(` <${obj}>`);
      } else if (obj.startsWith('"')) {
        // Literal
        lines.push(` ${obj}`);
      } else {
        // Plain literal
        lines.push(` "${obj}"`);
      }
      
      // Add comma if not last
      if (i < objects.length - 1) {
        lines.push(',');
      }
    }
  }

  /**
   * Shortens a URI using prefixes
   */
  private shortenUri(uri: string): string {
    // Check custom prefixes first
    for (const [prefix, prefixUri] of this.customPrefixes) {
      if (uri.startsWith(prefixUri)) {
        const localName = uri.substring(prefixUri.length);
        return `${prefix}:${localName}`;
      }
    }
    
    // Check built-in prefixes
    for (const [prefix, prefixUri] of Object.entries(PREFIXES)) {
      if (uri.startsWith(prefixUri)) {
        const localName = uri.substring(prefixUri.length);
        return `${prefix}:${localName}`;
      }
    }
    
    // No prefix found, return full URI
    return `<${uri}>`;
  }

  /**
   * Serializes to N-Triples format
   */
  private serializeNTriples(dataset: RdfDataset): string {
    const lines: string[] = [];
    
    for (const quad of dataset.quads) {
      const subject = quad.subject;
      const predicate = quad.predicate;
      const object = quad.object;
      const graph = quad.graph;
      
      // Escape special characters in literals
      const escapedObject = object.startsWith('"') 
        ? this.escapeLiteral(object) 
        : object;
      
      if (graph) {
        // Named graph
        lines.push(`<${subject}> <${predicate}> ${escapedObject} <${graph}> .`);
      } else {
        // Default graph
        lines.push(`<${subject}> <${predicate}> ${escapedObject} .`);
      }
    }
    
    return lines.join('\n');
  }

  /**
   * Escapes a literal for N-Triples
   */
  private escapeLiteral(literal: string): string {
    // Remove existing quotes
    let value = literal;
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.substring(1, value.length - 1);
    }
    
    // Escape special characters
    value = value
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
    
    return `"${value}"`;
  }

  /**
   * Serializes to JSON-LD format
   */
  private serializeJsonLd(dataset: RdfDataset): string {
    const items: Record<string, unknown>[] = [];
    
    // Group by subject
    const bySubject = new Map<string, RdfQuad[]>();
    for (const quad of dataset.quads) {
      if (!bySubject.has(quad.subject)) {
        bySubject.set(quad.subject, []);
      }
      bySubject.get(quad.subject)?.push(quad);
    }
    
    // Convert each subject group to JSON-LD
    for (const [subject, quads] of bySubject) {
      const item: Record<string, unknown> = { '@id': subject };
      
      // Group by predicate
      const byPredicate = new Map<string, string[]>();
      for (const quad of quads) {
        if (quad.graph) continue; // Skip named graphs for now
        
        if (!byPredicate.has(quad.predicate)) {
          byPredicate.set(quad.predicate, []);
        }
        byPredicate.get(quad.predicate)?.push(quad.object);
      }
      
      // Convert predicates to properties
      for (const [predicate, objects] of byPredicate) {
        const property = this.shortenUriForJsonLd(predicate);
        
        if (objects.length === 1) {
          item[property] = this.convertObjectToJsonLd(objects[0]);
        } else {
          item[property] = objects.map(obj => this.convertObjectToJsonLd(obj));
        }
      }
      
      items.push(item);
    }
    
    return JSON.stringify(items, null, 2);
  }

  /**
   * Shortens a URI for JSON-LD property names
   */
  private shortenUriForJsonLd(uri: string): string {
    // For JSON-LD, we need to use compact IRIs
    // This is a simplified version
    
    for (const [prefix, prefixUri] of Object.entries(PREFIXES)) {
      if (uri.startsWith(prefixUri)) {
        const localName = uri.substring(prefixUri.length);
        return `${prefix}:${localName}`;
      }
    }
    
    // If no prefix found, use the full URI
    return uri;
  }

  /**
   * Converts an object to JSON-LD representation
   */
  private convertObjectToJsonLd(object: string): unknown {
    if (object.startsWith('_:') || object.startsWith('?') || object.startsWith('$')) {
      // Blank node
      return { '@id': object };
    } else if (object.startsWith('http://') || object.startsWith('https://')) {
      // URI reference
      return { '@id': object };
    } else if (object.startsWith('"')) {
      // Literal
      const value = object.substring(1, object.length - 1);
      return { '@value': value };
    } else {
      // Plain literal
      return { '@value': object };
    }
  }

  /**
   * Serializes to RDF/XML format (simplified)
   */
  private serializeRdfXml(dataset: RdfDataset): string {
    // This is a simplified serializer. In production, use a proper RDF/XML library.
    throw new ValidationError(
      'RDF/XML serialization not implemented. Use Turtle or JSON-LD.',
      'format'
    );
  }

  // ==========================================================================
  // Validation
  // ==========================================================================

  /**
   * Validates a set of quads
   */
  private validateQuads(quads: RdfQuad[]): void {
    for (const quad of quads) {
      this.validateQuad(quad);
    }
  }

  /**
   * Validates a single quad
   */
  private validateQuad(quad: RdfQuad): void {
    // Subject must be URI or blank node
    if (!quad.subject || (typeof quad.subject !== 'string')) {
      throw new ValidationError('Quad subject must be a string (URI or blank node)', 'subject');
    }
    
    // Predicate must be URI
    if (!quad.predicate || !quad.predicate.startsWith('http://') && !quad.predicate.startsWith('https://')) {
      throw new ValidationError('Quad predicate must be a URI', 'predicate');
    }
    
    // Object must be present
    if (!quad.object && quad.object !== '') {
      throw new ValidationError('Quad object must be present', 'object');
    }
  }
}

// ============================================================================
// Exports
// ============================================================================

export default RdfCodec;
export type { RdfLiteral, RdfTerm };
export { NAMESPACES, PREFIXES };
