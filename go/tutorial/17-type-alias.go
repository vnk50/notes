// custom names for existing types
// Useful for readability or when transitioning code.
// For example, type ByteSize int64 creates a ByteSize type as an alias for int64
package main

import "fmt"

func main() {
	fmt.Println("Type Alias:")
	type ByteSize int64
	var x ByteSize = 1024

	fmt.Println("x=", x)
}
