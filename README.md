# Py-Vuln-Finder
"Software Security" MSc course group project. Grade: 16.82/20

## Introduction - Dangerous Information Flows

A large class of application vulnerabilities originates in programs that enable user input information to affect the values of certain parameters of security-sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions or variables (so-called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions or variables, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.

It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restricting the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.

**This project aimed to study how web vulnerabilities can be detected statically by means of taint and input sanitization analysis. We chose as a target web server-side programs encoded in the Python language. There exists a range of Python web frameworks, of which Django is the most widely used. However, this project's implementation is generic to the Python language, without restriction to web applications.**

The following code slice, which is written in Python, contains code lines that may impact a data flow between a certain entry point and a sensitive sink. The variable request (which for intuition can be seen as the request parameter of a Django view), is uninstantiated and can be understood as an entry point. It uses the ```MySQLCursor.execute()``` method, which executes the given database operation query.

```
uname = retrieve_uname(request)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
```

Inspecting this slice it is clear that the program from which the slice was extracted can potentially encode an SQL injection vulnerability. An attacker can inject a malicious username like ```' OR 1 = 1 --```, modifying the structure of the query and obtaining all users' passwords.

The tool aims to search in the slices for vulnerabilities according to inputted patterns, which specify for a given type of vulnerability its possible sources (a.k.a. entry points), sanitizers, and sinks:

* name of vulnerability (e.g., SQL injection)
* a set of entry points (e.g., request parameter),
* a set of sanitization functions (e.g., escape_string),
* a set of sensitive sinks (e.g., execute),
* and a flag indicating whether implicit flows are to be considered.

The tool should signal potential vulnerabilities and sanitization efforts: If it identifies a possible data flow from an entry point to a sensitive sink (according to the inputted patterns), it should report a potential vulnerability; if the data flow passes through a sanitization function, it should still report the vulnerability but also acknowledge the fact that its sanitization is possibly being addressed.

## The Tool

The py-vuln-finder tool analyses Python (version 3.9) code slices represented in the form of an Abstract Syntax Tree (AST), receiving two JSON files as input: one containing the code slices and another containing a list of vulnerability patterns. After the analysis is complete, the tool outputs a JSON file with the list of vulnerability objects found. The analysis is fully customizable to the inputted vulnerability patterns. In addition to the entry points specified in the patterns, by default, any uninstantiated variable that appears in the slice is to be considered as an entry point to all vulnerabilities being considered.
_Note: It is assumed that the parsing of the Python slices has been done and that the input files are well-formed._
The Figure below represents the input-output flow of this tool.

![The Py-Vuln-Finder Tool](https://github.com/HenriqueCandeias/Py-Vuln-Finder/blob/main/The%20Py-Vuln-Finder%20Tool.svg)

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

Running the tool using as inputs the above vulnerability patterns and the AST corresponding to the slice represented in _Introduction_ would result in the JSON output below.

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

## Usage

```python py-vuln-finder.py ast_slice.py.json patterns_to_analyse.json```

* ```ast_slice.py.json``` contains the AST corresponding to the slice to analyze for vulnerabilities and sanitizations;
* ```patterns_to_analyse.json``` contains the vulnerability patterns to use as a reference.

After running the tool, an output file with a complete report is created. In this example, it would be ```ast_slice.output.json```.
