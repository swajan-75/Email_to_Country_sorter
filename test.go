package main
import (
	"fmt"
	"sync"
)

func test_chan(wg *sync.WaitGroup, ch <-chan int , id int){
	defer wg.Done()
	val,ok := <- ch
		if !ok{
			fmt.Println("Channel closed, goroutine",id,"exiting")
		}
		fmt.Println("Goroutine",id,"received:",val)
}

func mainDemo(){
	var wg sync.WaitGroup
	wg.Add(4)
	 ch := make(chan int)
	 
	go test_chan(&wg,ch,1)
	go test_chan(&wg,ch,2)
	go test_chan(&wg,ch,3)
	go test_chan(&wg,ch,4)
	for i:=0;i<4;i++{
		ch <- i
	}
	close(ch)

	wg.Wait()

}