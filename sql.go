package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Interpreter holds the variables for execution.
type Interpreter struct {
	variables map[string]int
}

// NewInterpreter creates a new interpreter instance.
func NewInterpreter() *Interpreter {
	return &Interpreter{variables: make(map[string]int)}
}

// Interpret processes the code and executes the commands.
func (i *Interpreter) Interpret(code string) {
	// Split the code by lines
	lines := strings.Split(code, "\n")

	// Loop over each line and process it
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// If it's a print statement, process it
		if strings.HasPrefix(line, "print") {
			i.printStatement(line)
		} else {
			i.assignmentStatement(line)
		}
	}
}

// assignmentStatement handles variable assignments
func (i *Interpreter) assignmentStatement(line string) {
	// Regex to match variable assignment (e.g., let x = 10)
	re := regexp.MustCompile(`let (\w+) = (\d+);`)
	match := re.FindStringSubmatch(line)

	if len(match) == 3 {
		varName := match[1]
		value := match[2]
		// Store the value in the variables map
		i.variables[varName] = toInt(value)
	}
}

// printStatement handles print statements (e.g., print x;)
func (i *Interpreter) printStatement(line string) {
	// Regex to match print statements (e.g., print x;)
	re := regexp.MustCompile(`print (\w+);`)
	match := re.FindStringSubmatch(line)

	if len(match) == 2 {
		varName := match[1]
		// Check if the variable exists and print its value
		if value, ok := i.variables[varName]; ok {
			fmt.Println(value)
		} else {
			fmt.Println("Undefined variable:", varName)
		}
	}
}

// Helper function to convert a string to an integer
func toInt(str string) int {
	var result int
	fmt.Sscanf(str, "%d", &result)
	return result
}

func main() {
	// Sample code
	code := `
let x = 5;
let y = 10;
print x;
print y;
`

	// Create a new interpreter and run the code
	interpreter := NewInterpreter()
	interpreter.Interpret(code)
}
