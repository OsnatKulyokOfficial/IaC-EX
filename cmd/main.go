package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
)

// Declare a constant for the resource type being evaluated
const (
	resourceType = "toy_resource"
)

// The main function where execution begins
func main() {
	ctx := context.Background() // Initialize a new context
	// Declare variables for error handling and loading policies
	var err error
	var policies *loader.Result

	// Construct the absolute path to the policy file
	policyAbsolutePath, _ := filepath.Abs(fmt.Sprintf("policies/%v/policy.rego", resourceType))
	// Load the policy file, excluding directories and non-Rego files
	if policies, err = loader.NewFileLoader().Filtered([]string{policyAbsolutePath}, func(_ string, info os.FileInfo, _ int) bool {
		return !info.IsDir() && !strings.HasSuffix(info.Name(), bundle.RegoExt)
	}); err != nil {
		panic(err) // Handle loading errors
	}

	// Initialize the Rego compiler
	compiler :=
		ast.NewCompiler().
			WithEnablePrintStatements(true). // Enable print statements in Rego policies
			WithStrict(true). // Enable strict mode
			WithUnsafeBuiltins(map[string]struct{}{
				ast.HTTPSend.Name:   {}, // Disable unsafe built-in functions
				ast.OPARuntime.Name: {},
			})

	// Compile the loaded policy modules
	compiler.Compile(policies.ParsedModules())
	if compiler.Failed() {
		panic(compiler.Errors) // Handle compilation errors
	}

	// Read the resource declaration file
	resourceDeclarationFileAbsolutePath, _ := filepath.Abs(fmt.Sprintf("policies/%v/resource.json", resourceType))
	resourceFileContent, err := os.ReadFile(resourceDeclarationFileAbsolutePath)
	if err != nil {
		panic(err) // Handle file reading errors
	}

	var resourceFileInput map[string]any
	// Unmarshal the JSON content of the resource file into a map
	err = json.Unmarshal(resourceFileContent, &resourceFileInput)
	if err != nil {
		panic(err) // Handle JSON unmarshalling errors
	}

	// Prepare a Rego query to evaluate the resource file against the policies
	var preparedEvalQuery rego.PreparedEvalQuery
	if preparedEvalQuery, err =
		rego.New(
			rego.Compiler(compiler), // Use the compiled policies
			rego.PrintHook(topdown.NewPrintHook(os.Stdout)), // Set up a print hook for debug printing
			rego.Query("risk_path = data.example.analyze"), // Define the query to find risk paths
			rego.Input(resourceFileInput), // Set the input for the query as the resource file content
		).PrepareForEval(ctx); err != nil {
		panic(err) // Handle query preparation errors
	}

	// Execute the query and print the results
	var resultSet rego.ResultSet
	if resultSet, err = preparedEvalQuery.Eval(ctx); err != nil {
		panic(err) // Handle query evaluation errors
	}

	// Output the identified risks
	fmt.Println("Risk found in resource type: ", resourceFileInput["type"])
	fmt.Println("Risk Paths: ", resultSet[0].Bindings["risk_path"])
	fmt.Println("Risk Lines: <TODO>") // Placeholder for future implementation
}