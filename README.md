# Go Challenge 2 Entry
## Secure Echo Server
This is my submission to the second Go challenge competition (http://golang-challenge.com/go-challenge2/). It was great fun to write, many thanks to the organisers!

## Issues
The user-defined types don't behave well when they are `nil` (this seems to be a common theme with examples though). There is also an issue I missed which golint caught - the `ReadHeader` function shouldn't be exported.
