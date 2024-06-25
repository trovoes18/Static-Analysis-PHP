**Group 23**

96745  - João Nunes
96770  - Tiago Delgado
102173 - Daniel Adónis 

# Discovering vulnerabilities in PHP web applications

A large class of vulnerabilities in applications originates in programs that enable user input information to affect the values of certain parameters of security sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions or variables (so called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions or variables, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.
It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restricting the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.
The aim of this project is to study how web vulnerabilities can be detected statically by means of taint and input sanitization analysis. We choose as a target the PHP language.

## Run the tool

In order to run the tool to inputs must be given:
* the name of the JSON file containing the program slice to analyse, represented in the form of an Abstract Syntax Tree (e.g: *1b-basic-flow.json*);
* the name of the JSON file containing the list of vulnerability patterns to consider (e.g: *1a-basic-flow.patterns.json*);

For example:

```
python3 php-analyser.py slice.json patterns.json
```




