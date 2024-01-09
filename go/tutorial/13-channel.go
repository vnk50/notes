// Channels are used for communication between forouting (concurrent threads). THey can be synchronous or asynchornous
package main

import "fmt"

func main() {
	fmt.Println("channel:")
	u := make(chan int) // unbuffered channel of integers
	fmt.Println("u=", u)
}
