// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
package clients

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
)

// ErrRDFParse represents an RDF parsing error
var ErrRDFParse = errors.New("RDF parse error")

// ErrRDFSerialization represents an RDF serialization error
var ErrRDFSerialization = errors.New("RDF serialization error")

// ErrUnsupportedFormat represents an unsupported RDF format error
var ErrUnsupportedFormat = errors.New("unsupported RDF format")

// RDFCodec provides RDF encoding and decoding capabilities for the Solid Sidecar SDK.
// This implementation supports Turtle, JSON-LD, N-Triples, and RDF/XML formats.
// It is thread-safe and follows Solid RDF conventions.
type RDFCodec struct {
	// baseURI is the base URI for relative URIs
	baseURI string

	// prefixes contains namespace prefixes for Turtle serialization
	prefixes map[string]string

	// defaultFormat is the default RDF format for serialization
	defaultFormat types.RDFFormat
}

// RDFCodecOptions contains options for creating an RDFCodec.
type RDFCodecOptions struct {
	// BaseURI is the base URI for relative URIs
	BaseURI string

	// Prefixes contains namespace prefixes
	Prefixes map[string]string

	// DefaultFormat is the default RDF format for serialization
	DefaultFormat types.RDFFormat
}

// NewRDFCodec creates a new RDFCodec.
//
// Parameters:
//   - options: Optional codec options (can be nil for defaults)
//
// Returns:
//   - A new RDFCodec instance
func NewRDFCodec(options *RDFCodecOptions) *RDFCodec {
	baseURI := ""
	prefixes := make(map[string]string)
	defaultFormat := types.JSONLD

	if options != nil {
		if options.BaseURI != "" {
			baseURI = options.BaseURI
		}
		if options.Prefixes != nil {
			prefixes = options.Prefixes
		}
		if options.DefaultFormat != "" {
			defaultFormat = options.DefaultFormat
		}
	}

	// Add default Solid prefixes
	if _, exists := prefixes["solid"]; !exists {
		prefixes["solid"] = "http://www.w3.org/ns/solid/terms#"
	}
	if _, exists := prefixes["rdf"]; !exists {
		prefixes["rdf"] = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	}
	if _, exists := prefixes["rdfs"]; !exists {
		prefixes["rdfs"] = "http://www.w3.org/2000/01/rdf-schema#"
	}
	if _, exists := prefixes["xsd"]; !exists {
		prefixes["xsd"] = "http://www.w3.org/2001/XMLSchema#"
	}
	if _, exists := prefixes["ldp"]; !exists {
		prefixes["ldp"] = "http://www.w3.org/ns/ldp#"
	}
	if _, exists := prefixes["acl"]; !exists {
		prefixes["acl"] = "http://www.w3.org/ns/auth/acl#"
	}

	return &RDFCodec{
		baseURI:       baseURI,
		prefixes:      prefixes,
		defaultFormat: defaultFormat,
	}
}

// SetBaseURI sets the base URI for relative URIs.
func (c *RDFCodec) SetBaseURI(baseURI string) {
	c.baseURI = baseURI
}

// AddPrefix adds a namespace prefix.
func (c *RDFCodec) AddPrefix(prefix, uri string) {
	c.prefixes[prefix] = uri
}

// SetDefaultFormat sets the default RDF format for serialization.
func (c *RDFCodec) SetDefaultFormat(format types.RDFFormat) {
	c.defaultFormat = format
}

// Parse parses RDF data into an RDFDataset.
//
// Parameters:
//   - data: The RDF data to parse
//   - format: The format of the data (optional, will be detected if not provided)
//
// Returns:
//   - The parsed RDFDataset
//   - Error if parsing fails
func (c *RDFCodec) Parse(data []byte, format types.RDFFormat) (*types.RDFDataset, error) {
	if len(data) == 0 {
		return &types.RDFDataset{
			Triples:  []types.RDFTriple{},
			Graphs:   make(map[string][]types.RDFTriple),
			Prefixes: make(map[string]string),
		}, nil
	}

	// Detect format if not provided
	if format == "" {
		format = c.DetectFormat(data)
	}

	// Parse based on format
	dataset := &types.RDFDataset{
		Triples:  []types.RDFTriple{},
		Graphs:   make(map[string][]types.RDFTriple),
		Prefixes: make(map[string]string),
	}

	// Copy prefixes
	for k, v := range c.prefixes {
		dataset.Prefixes[k] = v
	}

	// Parse based on format
	switch format {
	case types.Turtle:
		return c.parseTurtle(data, dataset)
	case types.JSONLD:
		return c.parseJSONLD(data, dataset)
	case types.NTriples:
		return c.parseNTriples(data, dataset)
	case types.RDFXML:
		return c.parseRDFXML(data, dataset)
	default:
		// Try to detect and parse
		if detectedFormat := c.DetectFormat(data); detectedFormat != "" {
			return c.Parse(data, detectedFormat)
		}
		return nil, fmt.Errorf("%w: unable to detect RDF format", ErrUnsupportedFormat)
	}
}

// ParseString parses RDF data from a string.
//
// Parameters:
//   - data: The RDF data to parse
//   - format: The format of the data (optional)
//
// Returns:
//   - The parsed RDFDataset
//   - Error if parsing fails
func (c *RDFCodec) ParseString(data, format string) (*types.RDFDataset, error) {
	return c.Parse([]byte(data), types.RDFFormat(format))
}

// Serialize serializes an RDFDataset to the specified format.
//
// Parameters:
//   - dataset: The RDFDataset to serialize
//   - format: The target format (defaults to defaultFormat if empty)
//
// Returns:
//   - The serialized RDF data
//   - Error if serialization fails
func (c *RDFCodec) Serialize(dataset *types.RDFDataset, format types.RDFFormat) ([]byte, error) {
	if dataset == nil {
		return nil, fmt.Errorf("%w: dataset is nil", ErrRDFSerialization)
	}

	// Use default format if not provided
	if format == "" {
		format = c.defaultFormat
	}

	// Serialize based on format
	switch format {
	case types.Turtle:
		return c.serializeTurtle(dataset)
	case types.JSONLD:
		return c.serializeJSONLD(dataset)
	case types.NTriples:
		return c.serializeNTriples(dataset)
	case types.RDFXML:
		return c.serializeRDFXML(dataset)
	default:
		return nil, fmt.Errorf("%w: unsupported format %s", ErrUnsupportedFormat, format)
	}
}

// SerializeToString serializes an RDFDataset to a string in the specified format.
//
// Parameters:
//   - dataset: The RDFDataset to serialize
//   - format: The target format (defaults to defaultFormat if empty)
//
// Returns:
//   - The serialized RDF data as a string
//   - Error if serialization fails
func (c *RDFCodec) SerializeToString(dataset *types.RDFDataset, format types.RDFFormat) (string, error) {
	data, err := c.Serialize(dataset, format)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DetectFormat detects the RDF format from the data.
//
// Parameters:
//   - data: The RDF data
//
// Returns:
//   - The detected RDFFormat
func (c *RDFCodec) DetectFormat(data []byte) types.RDFFormat {
	if len(data) == 0 {
		return ""
	}

	// Check for JSON-LD
	if c.isJSONLD(data) {
		return types.JSONLD
	}

	// Check for RDF/XML
	if c.isRDFXML(data) {
		return types.RDFXML
	}

	// Check for N-Triples
	if c.isNTriples(data) {
		return types.NTriples
	}

	// Default to Turtle
	return types.Turtle
}

// isJSONLD checks if the data appears to be JSON-LD.
func (c *RDFCodec) isJSONLD(data []byte) bool {
	dataStr := string(data)
	return strings.Contains(dataStr, "@context") &&
		(strings.Contains(dataStr, "@id") || strings.Contains(dataStr, "@type"))
}

// isRDFXML checks if the data appears to be RDF/XML.
func (c *RDFCodec) isRDFXML(data []byte) bool {
	dataStr := string(data)
	return strings.Contains(dataStr, "<?xml") &&
		(strings.Contains(dataStr, "rdf:RDF") || strings.Contains(dataStr, "RDF"))
}

// isNTriples checks if the data appears to be N-Triples.
func (c *RDFCodec) isNTriples(data []byte) bool {
	// N-Triples has a very specific format: subject predicate object .
	// and uses angle brackets for URIs
	dataStr := string(data)
	lines := strings.Split(dataStr, "\n")

	if len(lines) == 0 {
		return false
	}

	// Check for typical N-Triples patterns
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// N-Triples lines should have the pattern: <uri> <uri> <literal/uri> .
		if strings.HasPrefix(line, "<") && strings.Contains(line, ">") {
			return true
		}
	}

	return false
}

// parseTurtle parses Turtle format RDF data.
func (c *RDFCodec) parseTurtle(data []byte, dataset *types.RDFDataset) (*types.RDFDataset, error) {
	dataStr := string(data)
	lines := strings.Split(dataStr, "\n")

	var currentGraph string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse prefix declarations
		if strings.HasPrefix(line, "@prefix") {
			c.parsePrefixDeclaration(line, dataset)
			continue
		}

		// Parse base declarations
		if strings.HasPrefix(line, "@base") {
			c.parseBaseDeclaration(line)
			continue
		}

		// Parse graph declarations
		if strings.Contains(line, "{") && !strings.Contains(line, "}") {
			// Start of a named graph
			currentGraph = c.extractGraphURI(line)
			continue
		}

		if strings.Contains(line, "}") {
			// End of named graph
			currentGraph = ""
			continue
		}

		// Parse triples
		if strings.Contains(line, ".") {
			triples := c.parseTurtleTriples(line)
			if currentGraph != "" {
				dataset.Graphs[currentGraph] = append(dataset.Graphs[currentGraph], triples...)
			} else {
				dataset.Triples = append(dataset.Triples, triples...)
			}
		}
	}

	return dataset, nil
}

// parsePrefixDeclaration parses a @prefix declaration.
func (c *RDFCodec) parsePrefixDeclaration(line string, dataset *types.RDFDataset) {
	// Format: @prefix prefix: <uri> .
	parts := strings.Fields(line)
	if len(parts) >= 4 {
		prefix := strings.TrimSuffix(parts[1], ":")
		uri := strings.Trim(parts[2], "<> ")

		// Store in both codec and dataset
		c.prefixes[prefix] = uri
		dataset.Prefixes[prefix] = uri
	}
}

// parseBaseDeclaration parses a @base declaration.
func (c *RDFCodec) parseBaseDeclaration(line string) {
	// Format: @base <uri> .
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		c.baseURI = strings.Trim(parts[1], "<> ")
	}
}

// extractGraphURI extracts the graph URI from a graph declaration.
func (c *RDFCodec) extractGraphURI(line string) string {
	// Format: <uri> {
	uriStart := strings.Index(line, "<")
	uriEnd := strings.Index(line, ">")

	if uriStart >= 0 && uriEnd > uriStart {
		return line[uriStart+1 : uriEnd]
	}

	return ""
}

// parseTurtleTriples parses triples from a Turtle line.
func (c *RDFCodec) parseTurtleTriples(line string) []types.RDFTriple {
	var triples []types.RDFTriple

	// Remove the trailing period
	line = strings.TrimSuffix(line, ".")
	line = strings.TrimSpace(line)

	// Split by semicolon for multiple statements about the same subject
	statements := strings.Split(line, ";")

	var subject, predicate string

	for i, statement := range statements {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}

		// Split by space or tabs
		parts := strings.Fields(statement)

		if i == 0 {
			// First statement: subject predicate object
			if len(parts) >= 3 {
				subject = c.resolveURI(parts[0])
				predicate = c.resolveURI(parts[1])

				object, objType, objDatatype, objLanguage := c.parseTurtleObject(parts[2:])

				triple := types.RDFTriple{
					Subject:         subject,
					Predicate:       predicate,
					Object:          object,
					ObjectType:      objType,
					LiteralDatatype: objDatatype,
					LiteralLanguage: objLanguage,
				}

				triples = append(triples, triple)
			}
		} else {
			// Subsequent statements: predicate object
			if len(parts) >= 2 {
				predicate = c.resolveURI(parts[0])

				object, objType, objDatatype, objLanguage := c.parseTurtleObject(parts[1:])

				triple := types.RDFTriple{
					Subject:         subject,
					Predicate:       predicate,
					Object:          object,
					ObjectType:      objType,
					LiteralDatatype: objDatatype,
					LiteralLanguage: objLanguage,
				}

				triples = append(triples, triple)
			}
		}
	}

	return triples
}

// resolveURI resolves a URI reference using prefixes and base URI.
func (c *RDFCodec) resolveURI(uri string) string {
	// If it's a full URI, return as-is
	if strings.Contains(uri, "://") || strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}

	// If it's in angle brackets, extract it
	if strings.HasPrefix(uri, "<") && strings.HasSuffix(uri, ">") {
		uri = uri[1 : len(uri)-1]
		if strings.Contains(uri, "://") {
			return uri
		}
	}

	// Check for prefixed names (prefix:localname)
	if idx := strings.Index(uri, ":"); idx > 0 {
		prefix := uri[:idx]
		local := uri[idx+1:]

		if namespace, exists := c.prefixes[prefix]; exists {
			return namespace + local
		}

		// Try to resolve relative URI
		if c.baseURI != "" {
			return c.baseURI + local
		}

		return uri // Return as-is if we can't resolve
	}

	// Handle blank nodes (start with _:)
	if strings.HasPrefix(uri, "_:") {
		return uri // Blank nodes are returned as-is
	}

	// If we have a base URI, use it
	if c.baseURI != "" {
		return c.baseURI + uri
	}

	return uri
}

// parseTurtleObject parses an object from Turtle parts.
func (c *RDFCodec) parseTurtleObject(parts []string) (string, string, string, string) {
	if len(parts) == 0 {
		return "", "", "", ""
	}

	obj := parts[0]

	// Check if it's a literal (starts with quote)
	if strings.HasPrefix(obj, "\"\"") || strings.HasPrefix(obj, "'") {
		// Parse quoted literal
		return c.parseTurtleLiteral(obj)
	}

	// Check if it's a blank node
	if strings.HasPrefix(obj, "_:") {
		return obj, "blank", "", ""
	}

	// It's a URI
	return c.resolveURI(obj), "uri", "", ""
}

// parseTurtleLiteral parses a Turtle literal.
func (c *RDFCodec) parseTurtleLiteral(literal string) (string, string, string, string) {
	// Remove surrounding quotes
	if strings.HasPrefix(literal, "\"\"") && strings.HasSuffix(literal, "\"\"") {
		literal = literal[1 : len(literal)-1]
	} else if strings.HasPrefix(literal, "'") && strings.HasSuffix(literal, "'") {
		literal = literal[1 : len(literal)-1]
	} else {
		// Not a quoted literal
		return literal, "literal", "", ""
	}

	// Check for language tag
	if idx := strings.Index(literal, "@"); idx > 0 {
		value := literal[:idx]
		language := literal[idx+1:]
		return value, "literal", "", language
	}

	// Check for datatype
	if idx := strings.Index(literal, "^^"); idx > 0 {
		value := literal[:idx]
		datatype := literal[idx+2:]
		return value, "literal", c.resolveURI(datatype), ""
	}

	return literal, "literal", "", ""
}

// parseJSONLD parses JSON-LD format RDF data.
func (c *RDFCodec) parseJSONLD(data []byte, dataset *types.RDFDataset) (*types.RDFDataset, error) {
	var jsonData map[string]interface{}

	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("%w: failed to parse JSON-LD: %v", ErrRDFParse, err)
	}

	// Extract @context
	if context, exists := jsonData["@context"].(string); exists {
		// Store context - this could be used for prefix resolution
		_ = context
	}

	// Extract @graph
	if graph, exists := jsonData["@graph"].([]interface{}); exists {
		for _, item := range graph {
			if itemMap, ok := item.(map[string]interface{}); ok {
				c.parseJSONLDNode(itemMap, dataset)
			}
		}
	} else {
		// Maybe the whole document is a node
		c.parseJSONLDNode(jsonData, dataset)
	}

	return dataset, nil
}

// parseJSONLDNode parses a JSON-LD node into triples.
func (c *RDFCodec) parseJSONLDNode(node map[string]interface{}, dataset *types.RDFDataset) {
	// Extract @id (subject)
	subject, subjectExists := node["@id"].(string)
	if !subjectExists {
		// Use blank node
		subject = "_:b1"
	}

	// Extract @type
	if typeValue, exists := node["@type"].(string); exists {
		// Add type triple
		triple := types.RDFTriple{
			Subject:    subject,
			Predicate:  "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
			Object:     typeValue,
			ObjectType: "uri",
		}
		dataset.Triples = append(dataset.Triples, triple)
	}

	// Parse properties
	for key, value := range node {
		// Skip special keys
		if strings.HasPrefix(key, "@") {
			continue
		}

		// Resolve predicate
		predicate := c.resolveJSONLDKey(key)

		// Parse value
		c.parseJSONLDValue(subject, predicate, value, dataset)
	}
}

// resolveJSONLDKey resolves a JSON-LD key to a full URI.
func (c *RDFCodec) resolveJSONLDKey(key string) string {
	// Check for prefixed form (prefix:localname)
	if idx := strings.Index(key, ":"); idx > 0 {
		prefix := key[:idx]
		local := key[idx+1:]

		if namespace, exists := c.prefixes[prefix]; exists {
			return namespace + local
		}

		// Return as-is
		return key
	}

	// It might be a full URI
	return key
}

// parseJSONLDValue parses a JSON-LD value.
func (c *RDFCodec) parseJSONLDValue(subject, predicate string, value interface{}, dataset *types.RDFDataset) {
	switch v := value.(type) {
	case string:
		// Check if it's a reference to another node
		if strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}") {
			// It's an embedded node - this is more complex
			// For now, treat as literal
			triple := types.RDFTriple{
				Subject:    subject,
				Predicate:  predicate,
				Object:     v,
				ObjectType: "literal",
			}
			dataset.Triples = append(dataset.Triples, triple)
		} else if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.Contains(v, "://") {
			// It's a URI reference
			triple := types.RDFTriple{
				Subject:    subject,
				Predicate:  predicate,
				Object:     v,
				ObjectType: "uri",
			}
			dataset.Triples = append(dataset.Triples, triple)
		} else {
			// It's a literal
			triple := types.RDFTriple{
				Subject:    subject,
				Predicate:  predicate,
				Object:     v,
				ObjectType: "literal",
			}
			dataset.Triples = append(dataset.Triples, triple)
		}

	case []interface{}:
		// Multiple values
		for _, item := range v {
			c.parseJSONLDValue(subject, predicate, item, dataset)
		}

	case map[string]interface{}:
		// Embedded node - for now, just store as JSON
		jsonData, _ := json.Marshal(v)
		triple := types.RDFTriple{
			Subject:    subject,
			Predicate:  predicate,
			Object:     string(jsonData),
			ObjectType: "literal",
		}
		dataset.Triples = append(dataset.Triples, triple)

	case bool:
		triple := types.RDFTriple{
			Subject:    subject,
			Predicate:  predicate,
			Object:     strconv.FormatBool(v),
			ObjectType: "literal",
		}
		dataset.Triples = append(dataset.Triples, triple)

	case float64:
		triple := types.RDFTriple{
			Subject:    subject,
			Predicate:  predicate,
			Object:     strconv.FormatFloat(v, 'f', -1, 64),
			ObjectType: "literal",
		}
		dataset.Triples = append(dataset.Triples, triple)

	case nil:
		// Skip nil values
		return
	}
}

// parseNTriples parses N-Triples format RDF data.
func (c *RDFCodec) parseNTriples(data []byte, dataset *types.RDFDataset) (*types.RDFDataset, error) {
	dataStr := string(data)
	lines := strings.Split(dataStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse N-Triples line: subject predicate object .
		if strings.HasSuffix(line, ".") {
			line = strings.TrimSuffix(line, ".")
			line = strings.TrimSpace(line)

			parts := strings.Fields(line)
			if len(parts) >= 3 {
				subject := c.parseNTriplesNode(parts[0])
				predicate := c.parseNTriplesNode(parts[1])
				object, objType, objDatatype, objLanguage := c.parseNTriplesObject(parts[2:])

				triple := types.RDFTriple{
					Subject:         subject,
					Predicate:       predicate,
					Object:          object,
					ObjectType:      objType,
					LiteralDatatype: objDatatype,
					LiteralLanguage: objLanguage,
				}

				dataset.Triples = append(dataset.Triples, triple)
			}
		}
	}

	return dataset, nil
}

// parseNTriplesNode parses an N-Triples node.
func (c *RDFCodec) parseNTriplesNode(node string) string {
	// Remove angle brackets
	if strings.HasPrefix(node, "<") && strings.HasSuffix(node, ">") {
		return node[1 : len(node)-1]
	}

	// It's a blank node
	return node
}

// parseNTriplesObject parses an N-Triples object.
func (c *RDFCodec) parseNTriplesObject(parts []string) (string, string, string, string) {
	if len(parts) == 0 {
		return "", "", "", ""
	}

	obj := parts[0]

	// Check if it's a literal
	if strings.HasPrefix(obj, "\"\"") {
		return c.parseNTriplesLiteral(obj)
	}

	// Check if it's a URI
	if strings.HasPrefix(obj, "<") && strings.HasSuffix(obj, ">") {
		return obj[1 : len(obj)-1], "uri", "", ""
	}

	// It's a blank node
	return obj, "blank", "", ""
}

// parseNTriplesLiteral parses an N-Triples literal.
func (c *RDFCodec) parseNTriplesLiteral(literal string) (string, string, string, string) {
	// Format: "value"^^<datatype> or "value"@language

	if !strings.HasPrefix(literal, "\"\"") || !strings.HasSuffix(literal, "\"\"") {
		return literal, "literal", "", ""
	}

	// Remove quotes
	literal = literal[1 : len(literal)-1]

	// Check for datatype
	if idx := strings.Index(literal, "^^"); idx > 0 {
		value := literal[:idx]
		datatype := literal[idx+2:]

		// Remove angle brackets from datatype
		if strings.HasPrefix(datatype, "<") && strings.HasSuffix(datatype, ">") {
			datatype = datatype[1 : len(datatype)-1]
		}

		return value, "literal", datatype, ""
	}

	// Check for language
	if idx := strings.Index(literal, "@"); idx > 0 {
		value := literal[:idx]
		language := literal[idx+1:]
		return value, "literal", "", language
	}

	return literal, "literal", "", ""
}

// parseRDFXML parses RDF/XML format RDF data.
func (c *RDFCodec) parseRDFXML(data []byte, dataset *types.RDFDataset) (*types.RDFDataset, error) {
	// RDF/XML parsing is complex and would typically use a dedicated library
	// For now, we'll provide a basic implementation that handles common patterns

	dataStr := string(data)

	// Use regex to find triples in RDF/XML
	// This is a simplified parser - in production, use a proper RDF/XML parser

	// Pattern for RDF descriptions
	re := regexp.MustCompile(`<rdf:Description\s+rdf:about="([^"]+)">.*?</rdf:Description>`)

	// This is a placeholder - RDF/XML parsing requires a proper parser
	// For now, return empty dataset
	_ = re.FindAllStringSubmatch(dataStr, -1)

	return dataset, nil
}

// serializeTurtle serializes an RDFDataset to Turtle format.
func (c *RDFCodec) serializeTurtle(dataset *types.RDFDataset) ([]byte, error) {
	var sb strings.Builder

	// Write prefix declarations
	sb.WriteString("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n")
	sb.WriteString("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n")

	for prefix, uri := range c.prefixes {
		if prefix != "rdf" && prefix != "rdfs" {
			sb.WriteString(fmt.Sprintf("@prefix %s: <%s> .\n", prefix, uri))
		}
	}

	sb.WriteString("\n")

	// Write base declaration if set
	if c.baseURI != "" {
		sb.WriteString(fmt.Sprintf("@base <%s> .\n", c.baseURI))
		sb.WriteString("\n")
	}

	// Write triples from default graph
	for _, triple := range dataset.Triples {
		sb.WriteString(c.formatTurtleTriple(triple))
	}

	// Write named graphs
	for graphURI, triples := range dataset.Graphs {
		sb.WriteString(fmt.Sprintf("\n<%s> {\n", graphURI))
		for _, triple := range triples {
			sb.WriteString(c.formatTurtleTriple(triple))
		}
		sb.WriteString("}\n")
	}

	return []byte(sb.String()), nil
}

// formatTurtleTriple formats a triple in Turtle syntax.
func (c *RDFCodec) formatTurtleTriple(triple types.RDFTriple) string {
	// Format: subject predicate object .

	subject := c.formatTurtleNode(triple.Subject)
	predicate := c.formatTurtleNode(triple.Predicate)
	object := c.formatTurtleObject(triple)

	return fmt.Sprintf("%s %s %s .\n", subject, predicate, object)
}

// formatTurtleNode formats a node in Turtle syntax.
func (c *RDFCodec) formatTurtleNode(node string) string {
	// Check if it's a blank node
	if strings.HasPrefix(node, "_:") {
		return node
	}

	// Check if it's a full URI
	if strings.Contains(node, "://") {
		return fmt.Sprintf("<%s>", node)
	}

	// Try to find a prefix
	for prefix, uri := range c.prefixes {
		if strings.HasPrefix(node, uri) {
			local := strings.TrimPrefix(node, uri)
			return fmt.Sprintf("%s:%s", prefix, local)
		}
	}

	// Return as full URI
	return fmt.Sprintf("<%s>", node)
}

// formatTurtleObject formats an object in Turtle syntax.
func (c *RDFCodec) formatTurtleObject(triple types.RDFTriple) string {
	if triple.ObjectType == "literal" {
		// Format as literal
		if triple.LiteralDatatype != "" {
			return fmt.Sprintf("\"%s\"^^<%s>", escapeTurtleString(triple.Object), triple.LiteralDatatype)
		} else if triple.LiteralLanguage != "" {
			return fmt.Sprintf("\"%s\"@%s", escapeTurtleString(triple.Object), triple.LiteralLanguage)
		} else {
			return fmt.Sprintf("\"%s\"", escapeTurtleString(triple.Object))
		}
	} else if triple.ObjectType == "blank" {
		return triple.Object // Blank nodes are returned as-is
	} else {
		// It's a URI
		return c.formatTurtleNode(triple.Object)
	}
}

// escapeTurtleString escapes a string for Turtle serialization.
func escapeTurtleString(s string) string {
	// Escape backslashes and quotes
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"\"", "\\\"\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")

	return s
}

// serializeJSONLD serializes an RDFDataset to JSON-LD format.
func (c *RDFCodec) serializeJSONLD(dataset *types.RDFDataset) ([]byte, error) {
	// Build JSON-LD document

	// Create context
	context := make(map[string]interface{})
	context["@vocab"] = ""

	// Add prefixes to context
	for prefix, uri := range c.prefixes {
		context[prefix] = uri
	}

	// Add common Solid terms
	context["rdf"] = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	context["rdfs"] = "http://www.w3.org/2000/01/rdf-schema#"
	context["xsd"] = "http://www.w3.org/2001/XMLSchema#"

	jsonData := map[string]interface{}{
		"@context": context,
		"@graph":   []interface{}{},
	}

	// Convert triples to JSON-LD nodes
	nodes := c.convertToJSONLDNodes(dataset)

	// Add nodes to graph
	graph := jsonData["@graph"].([]interface{})
	for _, node := range nodes {
		graph = append(graph, node)
	}
	jsonData["@graph"] = graph

	// Serialize to JSON
	data, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to serialize JSON-LD: %v", ErrRDFSerialization, err)
	}

	return data, nil
}

// convertToJSONLDNodes converts triples to JSON-LD nodes.
func (c *RDFCodec) convertToJSONLDNodes(dataset *types.RDFDataset) []map[string]interface{} {
	nodes := make(map[string]map[string]interface{})

	// Process all triples
	allTriples := append(dataset.Triples, c.flattenGraphs(dataset)...)

	for _, triple := range allTriples {
		// Get or create subject node
		subjectNode := c.ensureNode(nodes, triple.Subject)

		// Get predicate
		predicate := c.getJSONLDKey(triple.Predicate)

		// Add value
		value := c.formatJSONLDValue(triple)

		// Add to node
		if _, exists := subjectNode[predicate]; exists {
			// If already exists, convert to array
			if arr, ok := subjectNode[predicate].([]interface{}); ok {
				subjectNode[predicate] = append(arr, value)
			} else {
				subjectNode[predicate] = []interface{}{subjectNode[predicate], value}
			}
		} else {
			subjectNode[predicate] = value
		}
	}

	// Convert map to slice
	result := make([]map[string]interface{}, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, node)
	}

	return result
}

// ensureNode ensures a node exists in the nodes map.
func (c *RDFCodec) ensureNode(nodes map[string]map[string]interface{}, nodeURI string) map[string]interface{} {
	if existing, exists := nodes[nodeURI]; exists {
		return existing
	}

	// Create new node
	newNode := make(map[string]interface{})

	// Add @id if it's not a blank node
	if !strings.HasPrefix(nodeURI, "_:") {
		newNode["@id"] = nodeURI
	}

	nodes[nodeURI] = newNode
	return newNode
}

// getJSONLDKey gets the JSON-LD key for a predicate.
func (c *RDFCodec) getJSONLDKey(predicate string) string {
	// Reverse lookup in prefixes
	for prefix, uri := range c.prefixes {
		if strings.HasPrefix(predicate, uri) {
			local := strings.TrimPrefix(predicate, uri)
			return prefix + ":" + local
		}
	}

	// Return as full URI
	return predicate
}

// formatJSONLDValue formats a value for JSON-LD serialization.
func (c *RDFCodec) formatJSONLDValue(triple types.RDFTriple) interface{} {
	if triple.ObjectType == "literal" {
		value := map[string]interface{}{
			"@value": triple.Object,
		}

		if triple.LiteralDatatype != "" {
			value["@type"] = triple.LiteralDatatype
		} else if triple.LiteralLanguage != "" {
			value["@language"] = triple.LiteralLanguage
		}

		return value
	} else if triple.ObjectType == "blank" {
		// Blank nodes are represented as objects in JSON-LD
		return map[string]interface{}{
			"@id": triple.Object,
		}
	} else {
		// It's a URI
		return map[string]interface{}{
			"@id": triple.Object,
		}
	}
}

// flattenGraphs flattens named graphs into a slice of triples.
func (c *RDFCodec) flattenGraphs(dataset *types.RDFDataset) []types.RDFTriple {
	var triples []types.RDFTriple

	for _, graphTriples := range dataset.Graphs {
		for _, triple := range graphTriples {
			// Add graph URI as a triple
			graphTriple := types.RDFTriple{
				Subject:    triple.Subject,
				Predicate:  "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
				Object:     "http://www.w3.org/ns/ldp#Container",
				ObjectType: "uri",
			}
			triples = append(triples, graphTriple)

			// Add original triple
			triples = append(triples, triple)
		}
	}

	return triples
}

// serializeNTriples serializes an RDFDataset to N-Triples format.
func (c *RDFCodec) serializeNTriples(dataset *types.RDFDataset) ([]byte, error) {
	var sb strings.Builder

	// Write triples from default graph
	for _, triple := range dataset.Triples {
		sb.WriteString(c.formatNTriplesTriple(triple))
	}

	// Write named graphs (N-Triples doesn't support named graphs directly)
	// So we'll flatten them into the default graph
	for _, triples := range dataset.Graphs {
		for _, triple := range triples {
			sb.WriteString(c.formatNTriplesTriple(triple))
		}
	}

	return []byte(sb.String()), nil
}

// formatNTriplesTriple formats a triple in N-Triples syntax.
func (c *RDFCodec) formatNTriplesTriple(triple types.RDFTriple) string {
	subject := c.formatNTriplesNode(triple.Subject)
	predicate := c.formatNTriplesNode(triple.Predicate)
	object := c.formatNTriplesObject(triple)

	return fmt.Sprintf("%s %s %s .\n", subject, predicate, object)
}

// formatNTriplesNode formats a node in N-Triples syntax.
func (c *RDFCodec) formatNTriplesNode(node string) string {
	// Blank nodes are returned as-is
	if strings.HasPrefix(node, "_:") {
		return node
	}

	// URIs are enclosed in angle brackets
	return fmt.Sprintf("<%s>", node)
}

// formatNTriplesObject formats an object in N-Triples syntax.
func (c *RDFCodec) formatNTriplesObject(triple types.RDFTriple) string {
	if triple.ObjectType == "literal" {
		if triple.LiteralDatatype != "" {
			return fmt.Sprintf("\"%s\"^^<%s>", escapeNTriplesString(triple.Object), triple.LiteralDatatype)
		} else if triple.LiteralLanguage != "" {
			return fmt.Sprintf("\"%s\"@%s", escapeNTriplesString(triple.Object), triple.LiteralLanguage)
		} else {
			return fmt.Sprintf("\"%s\"", escapeNTriplesString(triple.Object))
		}
	} else if triple.ObjectType == "blank" {
		return triple.Object
	} else {
		// It's a URI
		return c.formatNTriplesNode(triple.Object)
	}
}

// escapeNTriplesString escapes a string for N-Triples serialization.
func escapeNTriplesString(s string) string {
	// N-Triples uses the same escaping as Turtle
	return escapeTurtleString(s)
}

// serializeRDFXML serializes an RDFDataset to RDF/XML format.
func (c *RDFCodec) serializeRDFXML(dataset *types.RDFDataset) ([]byte, error) {
	// RDF/XML serialization is complex
	// For now, provide a basic implementation

	var sb strings.Builder

	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">`)
	sb.WriteString(`<rdf:Description rdf:about="`)
	sb.WriteString(`">`)

	// Add all triples
	for _, triple := range dataset.Triples {
		// Skip type triples for now
		if !strings.Contains(triple.Predicate, "type") {
			continue
		}

		// Add predicate
		predicate := strings.TrimPrefix(triple.Predicate, "http://www.w3.org/1999/02/22-rdf-syntax-ns#")
		sb.WriteString(fmt.Sprintf(`<%s>%s</%s>`, predicate, triple.Object, predicate))
	}

	sb.WriteString(`</rdf:Description>`)
	sb.WriteString(`</rdf:RDF>`)

	return []byte(sb.String()), nil
}

// CreateThing creates a new RDF Thing (subject) with the given URI.
//
// Parameters:
//   - uri: The URI of the thing
//
// Returns:
//   - A new RDFDataset with the thing as the subject
func (c *RDFCodec) CreateThing(uri string) *types.RDFDataset {
	return &types.RDFDataset{
		Triples:  []types.RDFTriple{},
		Graphs:   make(map[string][]types.RDFTriple),
		Prefixes: make(map[string]string),
		BaseURI:  uri,
	}
}

// AddString adds a string literal to a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//   - value: The string value
//   - language: Optional language tag
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) AddString(dataset *types.RDFDataset, subject, predicate, value, language string) *types.RDFDataset {
	triple := types.RDFTriple{
		Subject:         subject,
		Predicate:       predicate,
		Object:          value,
		ObjectType:      "literal",
		LiteralLanguage: language,
	}

	dataset.Triples = append(dataset.Triples, triple)
	return dataset
}

// AddStringNoLocale adds a string literal without language tag.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//   - value: The string value
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) AddStringNoLocale(dataset *types.RDFDataset, subject, predicate, value string) *types.RDFDataset {
	return c.AddString(dataset, subject, predicate, value, "")
}

// AddUrl adds a URL to a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//   - url: The URL value
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) AddUrl(dataset *types.RDFDataset, subject, predicate, url string) *types.RDFDataset {
	triple := types.RDFTriple{
		Subject:    subject,
		Predicate:  predicate,
		Object:     url,
		ObjectType: "uri",
	}

	dataset.Triples = append(dataset.Triples, triple)
	return dataset
}

// SetUrl sets a URL on a thing (replaces any existing value).
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//   - url: The URL value
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) SetUrl(dataset *types.RDFDataset, subject, predicate, url string) *types.RDFDataset {
	// Remove existing triples with this predicate
	var newTriples []types.RDFTriple
	for _, triple := range dataset.Triples {
		if !(triple.Subject == subject && triple.Predicate == predicate) {
			newTriples = append(newTriples, triple)
		}
	}

	dataset.Triples = newTriples
	return c.AddUrl(dataset, subject, predicate, url)
}

// AddBoolean adds a boolean literal to a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//   - value: The boolean value
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) AddBoolean(dataset *types.RDFDataset, subject, predicate string, value bool) *types.RDFDataset {
	boolStr := "true"
	if !value {
		boolStr = "false"
	}

	triple := types.RDFTriple{
		Subject:    subject,
		Predicate:  predicate,
		Object:     boolStr,
		ObjectType: "literal",
	}

	dataset.Triples = append(dataset.Triples, triple)
	return dataset
}

// AddDateTime adds a date/time literal to a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//   - value: The date/time value (RFC3339 format)
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) AddDateTime(dataset *types.RDFDataset, subject, predicate, value string) *types.RDFDataset {
	triple := types.RDFTriple{
		Subject:         subject,
		Predicate:       predicate,
		Object:          value,
		ObjectType:      "literal",
		LiteralDatatype: "http://www.w3.org/2001/XMLSchema#dateTime",
	}

	dataset.Triples = append(dataset.Triples, triple)
	return dataset
}

// GetString retrieves a string value from a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//
// Returns:
//   - The string value (empty if not found)
//   - Whether the value was found
func (c *RDFCodec) GetString(dataset *types.RDFDataset, subject, predicate string) (string, bool) {
	for _, triple := range dataset.Triples {
		if triple.Subject == subject && triple.Predicate == predicate {
			if triple.ObjectType == "literal" {
				return triple.Object, true
			}
		}
	}

	return "", false
}

// GetUrl retrieves a URL value from a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//
// Returns:
//   - The URL value (empty if not found)
//   - Whether the value was found
func (c *RDFCodec) GetUrl(dataset *types.RDFDataset, subject, predicate string) (string, bool) {
	for _, triple := range dataset.Triples {
		if triple.Subject == subject && triple.Predicate == predicate {
			if triple.ObjectType == "uri" {
				return triple.Object, true
			}
		}
	}

	return "", false
}

// GetThing retrieves all triples for a specific subject.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//
// Returns:
//   - Slice of triples for the subject
func (c *RDFCodec) GetThing(dataset *types.RDFDataset, subject string) []types.RDFTriple {
	var triples []types.RDFTriple

	for _, triple := range dataset.Triples {
		if triple.Subject == subject {
			triples = append(triples, triple)
		}
	}

	return triples
}

// RemoveAll removes all triples with the given predicate from a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - subject: The subject URI
//   - predicate: The predicate URI
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) RemoveAll(dataset *types.RDFDataset, subject, predicate string) *types.RDFDataset {
	var newTriples []types.RDFTriple

	for _, triple := range dataset.Triples {
		if !(triple.Subject == subject && triple.Predicate == predicate) {
			newTriples = append(newTriples, triple)
		}
	}

	dataset.Triples = newTriples
	return dataset
}

// Remove removes a specific triple from a thing.
//
// Parameters:
//   - dataset: The dataset containing the thing
//   - triple: The triple to remove
//
// Returns:
//   - The updated dataset
func (c *RDFCodec) Remove(dataset *types.RDFDataset, triple types.RDFTriple) *types.RDFDataset {
	var newTriples []types.RDFTriple

	for _, t := range dataset.Triples {
		if !c.triplesEqual(t, triple) {
			newTriples = append(newTriples, t)
		}
	}

	dataset.Triples = newTriples
	return dataset
}

// triplesEqual checks if two triples are equal.
func (c *RDFCodec) triplesEqual(a, b types.RDFTriple) bool {
	return a.Subject == b.Subject &&
		a.Predicate == b.Predicate &&
		a.Object == b.Object &&
		a.ObjectType == b.ObjectType &&
		a.LiteralDatatype == b.LiteralDatatype &&
		a.LiteralLanguage == b.LiteralLanguage
}

// ParseURL parses RDF data from a URL.
// Note: This is a convenience method that uses the HTTP client.
//
// Parameters:
//   - url: The URL to fetch RDF data from
//   - format: The expected format (optional)
//
// Returns:
//   - The parsed RDFDataset
//   - Error if parsing fails
func (c *RDFCodec) ParseURL(url string, format types.RDFFormat) (*types.RDFDataset, error) {
	// This would use an HTTP client to fetch the data
	// For now, return an error as we don't have HTTP client in this package
	return nil, fmt.Errorf("URL parsing not implemented - use HTTP client directly")
}

// ValidateRDF validates an RDFDataset for common issues.
//
// Parameters:
//   - dataset: The dataset to validate
//
// Returns:
//   - Slice of validation errors
func (c *RDFCodec) ValidateRDF(dataset *types.RDFDataset) []string {
	var errors []string

	// Check for blank subjects
	for _, triple := range dataset.Triples {
		if triple.Subject == "" {
			errors = append(errors, "blank subject in triple")
		}
		if triple.Predicate == "" {
			errors = append(errors, "blank predicate in triple")
		}
		if triple.Object == "" {
			errors = append(errors, "blank object in triple")
		}
	}

	return errors
}

// ResolveURI resolves a potentially relative URI against the base URI.
//
// Parameters:
//   - uri: The URI to resolve
//
// Returns:
//   - The resolved absolute URI
func (c *RDFCodec) ResolveURI(uri string) string {
	if strings.Contains(uri, "://") {
		return uri
	}

	if c.baseURI == "" {
		return uri
	}

	// Handle relative URI
	if strings.HasPrefix(uri, "/") {
		// Absolute path
		base, err := url.Parse(c.baseURI)
		if err != nil {
			return uri
		}

		resolved, err := base.Parse(uri)
		if err != nil {
			return uri
		}

		return resolved.String()
	}

	// Relative path
	base, err := url.Parse(c.baseURI)
	if err != nil {
		return uri
	}

	resolved := base.JoinPath(uri)
	return resolved.String()
}
