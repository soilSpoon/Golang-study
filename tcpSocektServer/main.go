package main

import "fmt"

func f(a []int) {
	a[0]=10
}

func main() {
	a := make([]int, 2, 100)
	a[1] = 100
	f(a)
	fmt.Println(a[0])
}