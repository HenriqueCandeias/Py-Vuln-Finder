# Py-Vuln-Finder
"Software Security" MSc course group project. Grade: 16.82/20

## Introduction

### Dangerous Information Flows

A large class of application vulnerabilities originates in programs that enable user input information to affect the values of certain parameters of security-sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions or variables (so-called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions or variables, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.

It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restrict the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.

_**This project aimed to study how web vulnerabilities can be detected statically through taint and input sanitization analysis. We chose as a target web server-side programs encoded in the Python language. There exists a range of Python web frameworks, of which Django is the most widely used. However, this project's implementation is generic to the Python language, without restriction to web applications.**_

### Example of a Dangerous Information Flow

The following code slice, which is written in Python, contains code lines that may impact a data flow between a certain entry point and a sensitive sink. The variable request (which for intuition can be seen as the request parameter of a Django view), is uninstantiated and can be understood as an entry point. It uses the ```MySQLCursor.execute()``` method, which executes the given database operation query.

```
uname = retrieve_uname(request)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
```

Inspecting this slice it is clear that the program from which the slice was extracted can potentially encode an SQL injection vulnerability. An attacker can inject a malicious username like ```' OR 1 = 1 --```, modifying the structure of the query and obtaining all users' passwords.

### The Underlying Security Property

The security property that underlies this project is the following:

_**Given a set of vulnerability patterns of the form (vulnerability name, a set of entry points, a set of sensitive sinks, a set of sanitizing functions), a program is secure if it does not encode, for any given vulnerability pattern, an information flow from an entry point to a sensitive sink, unless the information goes through a sanitizing function.**_

## The Tool

The py-vuln-finder tool analyses Python (version 3.9) code slices represented in the form of an Abstract Syntax Tree (AST), receiving two JSON files as input: one containing the code slices and another containing a list of vulnerability patterns. After the analysis is complete, the tool outputs a JSON file with the list of vulnerability objects found. The Figure below represents the input-output flow of this tool.

![The Py-Vuln-Finder Tool](https://github.com/HenriqueCandeias/Py-Vuln-Finder/blob/main/The%20Py-Vuln-Finder%20Tool.svg)

Furthermore, the analysis is fully customizable to the inputted vulnerability patterns. In addition to the entry points specified in the patterns, by default, any uninstantiated variable that appears in the slice is to be considered as an entry point to all vulnerabilities being considered.

_Note: It is assumed that the parsing of the Python slices has been done and that the input files are well-formed._

Obs: Using the terms in the definition of the [Python's AST module],(https://greentreesnakes.readthedocs.io/en/latest/nodes.html#meet-the-nodes) the constructs considered for this tool were Literals (Constant), Variables (Name), Expressions (Expr, BinOp, Compare, Call, Attribute), Statements (Assign), Control flow (If and While).

### Vulnerability Patterns (Input)

The tool searches in the slices for vulnerabilities according to inputted patterns, which specify for a given type of vulnerability its possible sources (a.k.a. entry points), sanitizers, and sinks:

* name of vulnerability (e.g., SQL injection)
* a set of entry points (e.g., request parameter),
* a set of sanitization functions (e.g., escape_string),
* a set of sensitive sinks (e.g., execute),
* and a flag indicating whether implicit flows are to be considered.

The tool signals potential vulnerabilities and sanitization efforts: If it identifies a possible data flow from an entry point to a sensitive sink (according to the inputted patterns), it reports a potential vulnerability; if the data flow passes through a sanitization function, it still reports the vulnerability but also acknowledges the fact that its sanitization is possibly being addressed.

### Vulnerability Objects (Output)

The output of the program is a file with a JSON list of vulnerability objects. The structure of the objects should include 5 pairs, with the following meaning:

* "name": name of vulnerability (string, according to inputted pattern) Note: The only requirement is that the corresponding vulnerability name is a prefix of the name used in the output
* "source": input source (string, according to inputted pattern)
* "sink": sensitive sink (string, according to inputted pattern)
* "unsanitized flows": whether there are unsanitized flows (string)
* "sanitized flows": sanitizing functions if present, otherwise empty (list of lists of strings)

The output list includes a vulnerability object for every pair source-sink between which there is at least one flow of information. If at least one of the flows is not sanitized, it is signaled. Since there may be more than one flow path for a given pair source-sink, that could be sanitized in different ways, sanitized flows are represented as a list. Since each flow might be sanitized by more than one sanitizer, each flow is itself a list (with no particular order).

More precisely, the format of the output is:

```
<OUTPUT> ::= [ <VULNERABILITIES> ]
<VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>,<VULNERABILITIES>
<VULNERABILITY> ::= { "name":"<STRING>",
                      "source":"<STRING>",
                      "sink":"<STRING>",
                      "unsanitized flows": <YESNO>,
                      "sanitized flows": [ <FLOWS> ] }
<YESNO> ::= "yes" | "no"
<FLOWS> ::= "none" | <FLOW> | <FLOW>,<FLOWS>
<FLOW> ::= [ <SANITIZERS> ]
<SANITIZERS> ::= <STRING> | <STRING>,<SANITIZERS>
```

_(Note: A flow is said to be sanitized if it goes "through" the sanitizer, i.e., if at some point the entire information is converted into the output of a sanitizer.)_

## Usage

```python py-vuln-finder.py ast_slice.py.json patterns_to_analyse.json```

* ```ast_slice.py.json``` contains the AST corresponding to the slice to analyze for vulnerabilities and sanitizations;
* ```patterns_to_analyse.json``` contains the vulnerability patterns to use as a reference.

After running the tool, an output file with a complete report is created. In this example, it would be ```ast_slice.output.json```.

## Example

The AST corresponding to the Python program exemplified in _Introduction_ is present in the [python_ast_example.json](https://github.com/HenriqueCandeias/Py-Vuln-Finder/blob/main/python_ast_example.json) file (it is not displayed here because of its big size).

The JSON code below exemplifies a list of vulnerability patterns.

```
[
  {"vulnerability": "SQL injection A",
  "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
  "sanitizers": ["mogrify", "escape_string"],
  "sinks": ["execute"],
  "implicit": "no"},

  {"vulnerability": "SQL injection B",
  "sources": ["QueryDict", "ContactMailForm", "ChatMessageForm", "copy", "get_query_string"],
  "sanitizers": ["mogrify", "escape_string"],
  "sinks": ["raw", "RawSQL"],
  "implicit": "yes"},

  {"vulnerability": "XSS",
  "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
  "sanitizers": ["clean", "escape", "flatatt", "render_template", "render", "render_to_response"],
  "sinks": ["send_mail_jinja", "mark_safe", "Response", "Markup", "send_mail_jinja", "Raw"],
  "implicit": "no"}
]
```

Running the tool using as inputs the above vulnerability patterns and the previously mentioned AST would result in the JSON output below.

```
[
  {
    "vulnerability": "SQL injection A",
    "source": "request",
    "sink": "execute",
    "unsanitized flows": "yes",
    "sanitized flows": []
  }
]
```

## Critical Analysis and Improvements

Due to the nature of our implementation, mainly in the “While” constructs, we cannot guarantee that all information flows will be tracked precisely, mainly leading to possible false negatives. For example, a “While” construct that contains an illegal information flow that requires more than five recursive calls within itself to be revealed will not work with our approach. We preferred to sacrifice such in-depth precision for a slightly more superficial analysis. Also, our “Attribute” construct implementation is severely lacking, so it should also be considered as a source of such imprecise information flows. It is important to mention that when an argument of a function is tainted the remaining arguments can also become tainted. However, we do not consider that possibility in our tool. Similarly, when a class method or attribute gets tainted, we consider that the integrity state of the remaining methods/attributes of that class remains unchanged.

We also do not analyze the “break” and “continue” statements, so we are almost certain about the possibility of false positives. We also unduly report some implicit flows. For example:

```
if y:
  x = 42 # The value of x is always 42 no matter if it enters the if or the else
else:
  x = 42 # That way, x should not be considered tainted by the variable y
```

Regarding the sanitization mechanisms, we do not believe in the presence of either false negatives or false positives. It is not a possibility we fully discard, but throughout our testing and implementation, we did not come across any bugs or problems of the sort.

Although we cannot answer for certain how these vulnerabilities can be exploited, the only possibilities for false negatives that we know of are, as mentioned, running a While construct that requires more than five recursive calls to fully analyze and information flows passing through an “Attribute” construct.

Regarding reporting non-vulnerabilities and how we can avoid them, we would need to fully implement the “break” and “continue” constructs and also better develop the “Attribute” statement. For example, in the snippet ```a = b.c``` where ```c``` is a source, we declare both variables ```a``` and ```b``` as tainted when only ```a``` should be considered as such. We also need to, regarding the ```x=42``` false positive example, better verify if body statements are equal in loops and conditions with implicit flows so that we do not report false vulnerabilities.

Improving the precision of the tool can be done with further testing of possible corner cases mainly regarding implicit flows and complex and nested sanitizer usage. We would probably lose some efficiency with these improvements, since we are checking for more complex and specific vulnerabilities, but one can argue that efficiency is not the main worry, since the main properties that need to be assured for a program of this kind are completeness and robustness.

## Related Work

There are already several other tools that try to solve similar problems to ours. One of those, named [PyT](https://github.com/python-security/pyt), utilizes similar techniques, starting from an AST derived from some source code that is analyzed and deconstructed to reach an output that exposes potential vulnerabilities. While our tool analyses the AST itself to look for vulnerabilities, PyT traverses and converts the syntax trees into a control flow graph by its CFG component.

With that said, there is one tool where we took ideas from which technique to utilize. [Pythia](https://github.com/grnet/pythia), which mainly looks for XSS and CSRF defects and borrows some of the standard ideas from AST analysis, presents the following path traversal algorithm that was extremely useful to us in terms of inspiration to create our own recursive algorithm:

![Pythia Algorithm](https://github.com/HenriqueCandeias/Py-Vuln-Finder/blob/main/Pythia%20Path%20Traversal%20Algorithm.png)

References:

* [S. Micheelsen and B. Thalmann, "PyT - A Static Analysis Tool for Detecting Security Vulnerabilities in Python Web Applications", Master's Thesis, Aalborg University 2016](https://projekter.aau.dk/projekter/files/239563289/final.pdf)
* [V. Chibotaru et. al, "Scalable Taint Specification Inference with Big Code", PLDI 2019](https://files.sri.inf.ethz.ch/website/papers/scalable-taint-specification-inference-pldi2019.pdf)
* [L. Giannopoulos et. al, "Pythia: Identifying Dangerous Data-flows in Django-based Applications", EuroSec 2019](https://dimitro.gr/assets/papers/GDTM19.pdf)
