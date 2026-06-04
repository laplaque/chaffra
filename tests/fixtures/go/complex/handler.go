package handler

func SimpleHandler(x int) int {
	return x + 1
}

func ComplexHandler(x int, y int, mode string) int {
	if mode == "add" {
		if x > 0 {
			if y > 0 {
				return x + y
			} else {
				return x
			}
		} else {
			return y
		}
	} else if mode == "sub" {
		if x > y {
			return x - y
		} else {
			return y - x
		}
	} else if mode == "mul" {
		return x * y
	} else if mode == "div" {
		if y != 0 {
			return x / y
		}
		return 0
	} else {
		return 0
	}
}
