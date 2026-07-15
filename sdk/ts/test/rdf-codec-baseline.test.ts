import { RdfCodec } from '../src/clients/rdf-codec';
import { ValidationError } from '../src/types';

const EX = 'https://example.test/';

describe('RdfCodec baseline hardening', () => {
  it('preserves hash and semicolon characters inside literals and IRIs', () => {
    const codec = new RdfCodec();
    const dataset = codec.parse(`
      @prefix ex: <${EX}> .
      ex:me ex:name "Alice #1; Admin" ;
        ex:storage <${EX}storage/#primary> . # trailing comment
    `, 'text/turtle');

    expect(dataset.quads).toEqual([
      { subject: `${EX}me`, predicate: `${EX}name`, object: '"Alice #1; Admin"' },
      { subject: `${EX}me`, predicate: `${EX}storage`, object: `${EX}storage/#primary` },
    ]);
  });

  it('supports comma object lists and dotted prefixed names without splitting statements', () => {
    const codec = new RdfCodec();
    const dataset = codec.parse(`
      @prefix ex: <${EX}> .
      ex:me.v1 ex:knows ex:bob.v2, ex:carol.v3 .
    `, 'text/turtle');

    expect(dataset.quads.map(quad => quad.object)).toEqual([
      `${EX}bob.v2`,
      `${EX}carol.v3`,
    ]);
  });

  it('rejects relative IRIs when no base directive is present', () => {
    const codec = new RdfCodec();
    expect(() => codec.parse('<me> <https://example.test/name> "Alice" .', 'text/turtle'))
      .toThrow(ValidationError);
  });

  it('resolves relative IRIs only against an explicit base', () => {
    const codec = new RdfCodec();
    const dataset = codec.parse(`
      @base <${EX}profile/> .
      <card#me> <${EX}name> "Alice" .
    `, 'text/turtle');
    expect(dataset.quads[0]?.subject).toBe(`${EX}profile/card#me`);
  });

  it('enforces maxQuads during ingestion', () => {
    const codec = new RdfCodec({ maxQuads: 1 });
    expect(() => codec.parse(`
      <${EX}a> <${EX}p> <${EX}b> .
      <${EX}c> <${EX}p> <${EX}d> .
    `, 'application/n-triples')).toThrow('Exceeded maximum quad count');
  });

  it('parses expanded JSON-LD without empty terms or lossy placeholder quads', () => {
    const codec = new RdfCodec();
    const dataset = codec.parse(JSON.stringify({
      '@id': `${EX}me`,
      '@type': `${EX}Person`,
      [`${EX}name`]: { '@value': 'Alice', '@language': 'en' },
      [`${EX}knows`]: { '@id': `${EX}bob` },
    }), 'application/ld+json');

    expect(dataset.quads).toEqual([
      {
        subject: `${EX}me`,
        predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
        object: `${EX}Person`,
      },
      { subject: `${EX}me`, predicate: `${EX}name`, object: '"Alice"@en' },
      { subject: `${EX}me`, predicate: `${EX}knows`, object: `${EX}bob` },
    ]);
  });

  it('fails closed for unsupported RDF/XML', () => {
    const codec = new RdfCodec();
    expect(() => codec.parse('<rdf:RDF />', 'application/rdf+xml'))
      .toThrow('RDF/XML is not supported');
    expect(() => codec.serialize({ quads: [], formats: [] }, 'application/rdf+xml'))
      .toThrow('RDF/XML is not supported');
  });

  it('preserves defaults when optional config fields are explicitly undefined', () => {
    const codec = new RdfCodec({
      defaultInputFormat: undefined,
      defaultOutputFormat: undefined,
      logger: undefined,
    });
    expect(codec.getConfig().defaultInputFormat).toBe('text/turtle');
    expect(codec.getConfig().defaultOutputFormat).toBe('text/turtle');
  });

  it('creates deterministic collision-free blank node identifiers per codec instance', () => {
    const codec = new RdfCodec();
    expect(codec.createBlankNodeId()).toBe('_:b1');
    expect(codec.createBlankNodeId()).toBe('_:b2');
  });

  it('canonicalizes output deterministically', () => {
    const codec = new RdfCodec();
    const canonical = codec.parseCanonical(`
      <${EX}z> <${EX}p> <${EX}b> .
      <${EX}a> <${EX}p> "value" .
    `, 'application/n-triples');
    expect(canonical).toBe(
      `<${EX}a> <${EX}p> "value" .\n<${EX}z> <${EX}p> <${EX}b> .\n`
    );
  });
});
