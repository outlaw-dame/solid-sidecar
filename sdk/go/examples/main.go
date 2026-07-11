// Package main provides examples of using the Solid Sidecar Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/auth"
	"github.com/outlaw-dame/solid-sidecar/sdk/go/clients"
	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
)

// Example usage of the Solid Sidecar Go SDK
func main() {
	// Example 1: Basic resource operations with access token
	fmt.Println("=== Example 1: Basic Resource Operations ===")

	// Create a resource client
	resourceClient, err := clients.NewResourceClient("https://sidecar.example.com", nil)
	if err != nil {
		log.Fatalf("Failed to create resource client: %v", err)
	}

	// Set access token (in real usage, get this from OAuth2 flow)
	resourceClient.SetAccessToken("your-dpop-access-token")

	// Example: Get a resource
	ctx := context.Background()
	resource, err := resourceClient.Get(ctx, "/container/resource.ttl", nil)
	if err != nil {
		fmt.Printf("Failed to get resource: %v\n", err)
	} else {
		fmt.Printf("Got resource: %s\n", resource.URI)
		fmt.Printf("ETag: %s\n", resource.ETag)
		fmt.Printf("Content-Type: %s\n", resource.ContentType)
	}

	// Example 2: Create a resource with conditional write
	fmt.Println("\n=== Example 2: Create Resource (Create-Only) ===")

	createResult, err := resourceClient.Create(
		ctx,
		"/container/new-resource.ttl",
		"text/turtle",
		[]byte("@prefix ex: <http://example.org/ns#> .\nex:subject ex:predicate \"value\" ."),
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to create resource: %v\n", err)
	} else {
		fmt.Printf("Created resource with ETag: %s\n", createResult.ETag)
	}

	// Example 3: Update a resource with conditional write
	fmt.Println("\n=== Example 3: Update Resource (Conditional) ===")

	// First, get the current ETag
	currentETag, err := resourceClient.GetETag(ctx, "/container/existing.ttl", nil)
	if err != nil {
		fmt.Printf("Failed to get ETag: %v\n", err)
		return
	}

	updateResult, err := resourceClient.Update(
		ctx,
		"/container/existing.ttl",
		"text/turtle",
		[]byte("@prefix ex: <http://example.org/ns#> .\nex:subject ex:predicate \"updated value\" ."),
		currentETag,
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to update resource: %v\n", err)
		// This might be ErrResourceModified if someone else changed it
	} else {
		fmt.Printf("Updated resource with new ETag: %s\n", updateResult.ETag)
	}

	// Example 4: Delete a resource with conditional check
	fmt.Println("\n=== Example 4: Delete Resource (Conditional) ===")

	// Get current ETag for the resource to delete
	currentETag, err = resourceClient.GetETag(ctx, "/container/to-delete.ttl", nil)
	if err != nil {
		fmt.Printf("Failed to get ETag: %v\n", err)
		return
	}

	err = resourceClient.DeleteConditional(ctx, "/container/to-delete.ttl", currentETag, nil)
	if err != nil {
		fmt.Printf("Failed to delete resource: %v\n", err)
		// This might be ErrResourceModified if someone else changed it
		// or ErrResourceNotFound if it doesn't exist
	} else {
		fmt.Println("Successfully deleted resource")
	}

	// Example 5: List container contents
	fmt.Println("\n=== Example 5: List Container ===")

	listResult, err := resourceClient.List(ctx, "/container/", nil)
	if err != nil {
		fmt.Printf("Failed to list container: %v\n", err)
	} else {
		fmt.Printf("Container ETag: %s\n", listResult.ETag)
		fmt.Printf("Resources: %v\n", listResult.Resources)
		fmt.Printf("Containers: %v\n", listResult.Containers)
	}

	// Example 6: DPoP Authentication with AuthManager
	fmt.Println("\n=== Example 6: DPoP Authentication ===")

	authManager, err := auth.NewAuthManager(&auth.AuthManagerOptions{
		Issuer:       "https://oidc-issuer.example.com",
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		RedirectURI:  "https://yourapp.com/callback",
		Scope:        "openid profile",
		AutoRefresh:  true,
	})
	if err != nil {
		log.Fatalf("Failed to create auth manager: %v", err)
	}

	// Set a token (in real usage, you'd get this from ExchangeCode)
	authManager.SetToken("your-access-token", 3600)

	// Create a resource client with DPoP support
	resourceClientWithDPoP, err := clients.NewResourceClient("https://sidecar.example.com", nil)
	if err != nil {
		log.Fatalf("Failed to create resource client: %v", err)
	}

	// Set the DPoP proof function
	resourceClientWithDPoP.SetDPoPProofFunc(authManager.GetDPoPProofFunc())

	// Now all requests will automatically include DPoP proofs
	resource, err = resourceClientWithDPoP.Get(ctx, "/protected/resource.ttl", nil)
	if err != nil {
		fmt.Printf("Failed to get protected resource: %v\n", err)
	} else {
		fmt.Printf("Got protected resource: %s\n", resource.URI)
	}

	// Example 7: Create a container
	fmt.Println("\n=== Example 7: Create Container ===")

	containerType := "http://www.w3.org/ns/ldp#BasicContainer"
	containerResult, err := resourceClient.CreateContainer(
		ctx,
		"/new-container/",
		containerType,
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to create container: %v\n", err)
	} else {
		fmt.Printf("Created container with ETag: %s\n", containerResult.ETag)
	}

	// Example 8: Conditional PUT with preconditions
	fmt.Println("\n=== Example 8: Conditional PUT ===")

	// Use PutConditional for fine-grained control
	writeResult, err := resourceClient.PutConditional(
		ctx,
		"/container/resource.ttl",
		"text/turtle",
		[]byte("@prefix ex: <http://example.org/ns#> .\nex:updated ex:value \"new\" ."),
		"\"current-etag\"", // If-Match: only update if ETag matches
		"",                 // If-None-Match: empty means don't check
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to put conditionally: %v\n", err)
		// This will be ErrPreconditionFailed if ETag doesn't match
	} else {
		fmt.Printf("Conditional PUT succeeded, new ETag: %s\n", writeResult.ETag)
	}

	// Example 9: Create-only with If-None-Match
	fmt.Println("\n=== Example 9: Create-Only ===")

	writeResult, err = resourceClient.PutConditional(
		ctx,
		"/container/new-unique-resource.ttl",
		"text/turtle",
		[]byte("@prefix ex: <http://example.org/ns#> .\nex:new ex:value \"created\" ."),
		"",  // If-Match: empty means don't check
		"*", // If-None-Match: * means create only if doesn't exist
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to create uniquely: %v\n", err)
		// This will be ErrPreconditionFailed if resource already exists
	} else {
		fmt.Printf("Create-only succeeded, new ETag: %s\n", writeResult.ETag)
	}

	// Example 10: Using WritePreconditions struct
	fmt.Println("\n=== Example 10: Using WritePreconditions ===")

	preconditions := &types.WritePreconditions{
		IfMatch:     []string{"\"current-etag\""},
		IfNoneMatch: []string{}, // Empty slice means don't check
	}

	writeResult, err = resourceClient.Put(
		ctx,
		"/container/resource.ttl",
		"text/turtle",
		[]byte("@prefix ex: <http://example.org/ns#> .\nex:updated ex:value \"with struct\" ."),
		preconditions,
		nil,
	)
	if err != nil {
		fmt.Printf("Failed with preconditions: %v\n", err)
	} else {
		fmt.Printf("Write with preconditions succeeded, new ETag: %s\n", writeResult.ETag)
	}

	fmt.Println("\n=== Examples Complete ===")
}
