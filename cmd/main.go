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

type SubResource struct {
    Name      string   `json:"name"`
    Encrypted *bool    `json:"encrypted,omitempty"`
    ACL       []string `json:"acl"`
}

type Resource struct {
    Type                   string         `json:"type"`
    SubResourcePermissions []SubResource `json:"sub_resource_permissions"`
}

func analyzeSubResources(data []byte) map[string]int {
    var resource Resource
    if err := json.Unmarshal(data, &resource); err != nil {
        fmt.Println("Error parsing JSON:", err)
        return nil
    }

    baseLineNumber := 4 // Adjust based on actual JSON structure
    lineStep := 9       // Adjust based on actual JSON structure

    lineNumbers := make(map[string]int)

    for index, sub := range resource.SubResourcePermissions {
        lineNumber := baseLineNumber + (index * lineStep)
        if sub.Encrypted != nil {
            if *sub.Encrypted {
                lineNumbers[sub.Name] = lineNumber
            } else {
                lineNumbers[sub.Name] = lineNumber + 1
            }
        } else {
            lineNumbers[sub.Name] = lineNumber - 1
        }
    }
    return lineNumbers
}

func findCommonSubResources(riskPaths []interface{}, lineNumbers map[string]int) map[string]int {
    commonSubResources := make(map[string]int)

    // Iterate through each risk path
    for _, path := range riskPaths {
        // Convert the path interface to a string
        pathStr, ok := path.(string)
        if !ok {
            fmt.Println("Error: Risk path is not a string")
            continue
        }

        // Extract the numerical index from the risk path
        parts := strings.Split(pathStr, ".")
        if len(parts) != 3 {
            fmt.Println("Error: Invalid risk path format")
            continue
        }
        indexStr := parts[1]

        // Construct the sub-resource key using the extracted index
        subResourceKey := "sub_resource_" + indexStr

        // Check if the sub-resource key exists in the lineNumbers map
        if line, found := lineNumbers[subResourceKey]; found {
            // Add the common sub-resource key and its line number to the result map
            commonSubResources[subResourceKey] = line
        }
    }

    return commonSubResources
}

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

    var resourceFileInput map[string]interface{}
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

    // Call analyzeSubResources with resource JSON data
    lineNumbers := analyzeSubResources(resourceFileContent)

    // Extract names from "Risk Paths" and associate with their line numbers
    riskPaths := resultSet[0].Bindings["risk_path"].([]interface{})

    // Call findCommonSubResources to find common sub-resources
    riskLines := findCommonSubResources(riskPaths, lineNumbers)

    // Extract values from the map and store them in a slice
    var riskLinesList []string
    for _, v := range riskLines {
        riskLinesList = append(riskLinesList, fmt.Sprintf("%d", v))
    }

    // Print the list of values
    fmt.Println("risk:", riskLinesList)
}
