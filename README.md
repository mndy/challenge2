# Secure Echo Server. Go Challenge 2 Entry
This is my submission to the second Go challenge competition (http://golang-challenge.com/go-challenge2/). It was great fun to write, many thanks to the organisers!

## Issues
I think the main issues with it are the types I definied not behaving well when they are `nil` (this seems to be a common theme with examples though), and an issue I missed which golint caught - the `ReadHeader` function shouldn't be exported. It's also maybe a little overcomplicated, and could probably be made to do less allocations. 
