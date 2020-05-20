package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/zqz/fw/tcpdump"
)

func main() {
	fmt.Println("vim-go")
	sc := bufio.NewScanner(os.Stdin)

	needNextLine := false
	line := ""

	for sc.Scan() {
		l := sc.Text()

		if needNextLine {
			line += l
			needNextLine = false
			p := tcpdump.ParseIPV4Line(line)
			// sp
			fmt.Println("got ipv4 line", p.Src, "->", p.Dst, "(", p.Length, ")")
			continue
		}

		if tcpdump.DetermineProtocol(l) == "IP " {
			line = l
			needNextLine = true
			continue
		}

		fmt.Println("rejecting line")
	}

	if err := sc.Err(); err != nil {
		log.Println("err")
	}
}
