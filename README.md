# Cloud Security Flow Log Parser

## Project goal
The goal of this project is to parse flow log data from cloud security software and map each row to a tag based on a lookup table.

## Important files
- `FlowLogParser.java`: Main Java file containing the parsing logic
- `lookup_table.csv`: CSV file defining the lookup table for tagging
- `vpc_flow_logs.txt`: Sample input file containing flow log data

## To use this parser
1. Clone the repository
2. Ensure you have Java installed (version 8 or higher)
3. Compile the Java file: `javac FlowLogParser.java`
4. Run the parser: `java FlowLogParser`
5. Check the output file `output_results.txt` for results

## Assumptions
- Supports only the default log format and version 2 of VPC flow logs
- Input files are UTF-8 encoded
- The lookup table CSV file has a header row
- The flow log file contains valid data in the expected format

## Future improvements
- Add error handling and logging
- Implement unit tests
- Add command-line arguments for file paths
- Optimize for larger datasets

