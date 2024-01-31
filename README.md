# Py-Vuln-Finder
"Software Security" MSc course group project. Grade: 16.82/20

A large class of vulnerabilities in applications originates in programs that enable user input information to affect the values of certain parameters of security-sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions or variables (so-called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions or variables, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.

It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restricting the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.

This project aimed to study how web vulnerabilities can be detected statically by means of taint and input sanitization analysis. We chose as a target web server-side programs encoded in the Python language. There exists a range of Web frameworks for Python, of which Django is the most widely used.

More specifically, the py-vuln-finder tool analyses Python code slices represented in the form of an Abstract Syntax Tree (AST), receiving two JSON files as input - one containing the slices and another containing a list of vulnerability patterns -, and outputting a third JSON file with the list of vulnerability objects found by the tool.

It is assumed that the parsing of the Python slices has been done and that the input files are well-formed. The analysis is fully customizable to the inputted vulnerability patterns. In addition to the entry points specified in the patterns, by default, any uninstantiated variable that appears in the slice is to be considered as an entry point to all vulnerabilities being considered.

## Usage

```python py-vuln-finder.py ast_slice.py.json patterns_to_analyse.json```,

Where
* ```ast_slice.py.json``` is the slice to analyze for vulnerabilities and sanitizations;
* ```patterns_to_analyse.json``` is the patterns we will check.

After running the tool, an output file with a complete report is created. For example, for a code flow where an entry point ```c``` taints a sensitive sink ```e```, the output will look something like this:

![Output File Example]()
