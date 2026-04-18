# deadcode

`deadcode` is a small tool for collecting branch coverage from an executable at runtime.
The current implementation targets Windows, launches a process under the debugger, places breakpoints on jump instructions, records whether each branch was taken, and writes the results to a JSON file.