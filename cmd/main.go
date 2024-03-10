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

const (
	resourceType = "toy_resource"
)

func main() {
	ctx := context.Background()
	// load risk policies
	var err error
	var policies *loader.Result

	policyAbsolutePath, _ := filepath.Abs(fmt.Sprintf("policies/%v/policy.rego", resourceType))
	if policies, err = loader.NewFileLoader().Filtered([]string{policyAbsolutePath}, func(_ string, info os.FileInfo, _ int) bool {
		return !info.IsDir() && !strings.HasSuffix(info.Name(), bundle.RegoExt)
	}); err != nil {
		panic(err)
	}

	compiler :=
		ast.NewCompiler().
			WithEnablePrintStatements(true).
			WithStrict(true).
			WithUnsafeBuiltins(map[string]struct{}{
				ast.HTTPSend.Name:   {},
				ast.OPARuntime.Name: {},
			})

	// compile risk policies
	compiler.Compile(policies.ParsedModules())
	if compiler.Failed() {
		panic(compiler.Errors)
	}

	// read resource declaration file
	resourceDeclarationFileAbsolutePath, _ := filepath.Abs(fmt.Sprintf("policies/%v/resource.json", resourceType))
	resourceFileContent, err := os.ReadFile(resourceDeclarationFileAbsolutePath)
	if err != nil {
		panic(err)
	}

	var resourceFileInput map[string]any
	err = json.Unmarshal(resourceFileContent, &resourceFileInput)
	if err != nil {
		panic(err)
	}

	// query the resource declaration file for risks
	var preparedEvalQuery rego.PreparedEvalQuery
	if preparedEvalQuery, err =
		rego.New(
			rego.Compiler(compiler),
			rego.PrintHook(topdown.NewPrintHook(os.Stdout)),
			rego.Query("risk_path = data.example.analyze"),
			rego.Input(resourceFileInput),
		).PrepareForEval(ctx); err != nil {
		panic(err)
	}

	// print the resultant risks
	var resultSet rego.ResultSet
	if resultSet, err = preparedEvalQuery.Eval(ctx); err != nil {
		panic(err)
	}

	fmt.Println("Risk found in resource type: ", resourceFileInput["type"])
	fmt.Println("Risk Paths: ", resultSet[0].Bindings["risk_path"])
	fmt.Println("Risk Lines: <TODO>")
}
