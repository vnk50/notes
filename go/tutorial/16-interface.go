/*
Interface types : Method sets
Method sets:
Interfaces define sets of method. A type implements an interface by implementing its methods. They are central to
Go's type system and polymorphism
*/
package main

import "fmt"

type Geometry interface {
	Area() float64
	Perimeter() float64
}

type Rect struct {
	Width, Height float64
}

func (r Rect) Area() float64 {
	return r.Width * r.Height
}

func (r Rect) Perimeter() float64 {
	return 2 * (r.Width + r.Height)
}

func main() {
	fmt.Println("interface:")

	var w Geometry = Rect{3, 4}

	fmt.Println("w=", w)

	fmt.Println("Area=", w.Area())

	fmt.Println("Perimeter=", w.Perimeter())
}
