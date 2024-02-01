from code import interact
import sys
import json
import ast
import copy
import collections

found_vulns = []


def find_vulnerabilities(vuln_name, sources, sanitizers, sinks, implicit):

    class IntegrityState():

        def __init__(self, sources, sanitizers):
            
            #Taintedness
            self.tainted_variables = {}   #Key = source Value = tainted variables (NOT SINKS)
            self.tainted_paths = {}       #Key = sources Value = sinks
            self.instantiated_variables = [] #All initialized variables

            #Sanitization
            self.sanitized_variables = {} #Key = sanitizer Value = (Dictionary -> Key = source Value = list of sanitized variables)
            self.sanitized_paths = {} #Key = sanitizer Value = (Dictionary -> Key = source Value = sinks and other sanitizers)
            self.unsanitized_flows = {} #Key = bool (yes/no) Value = List of pair source-sink)


            for source in sources:
                self.tainted_variables[source] = []
                self.tainted_paths[source] = []    

            for sanitizer in sanitizers:
                self.sanitized_variables[sanitizer] = {}
                self.sanitized_paths[sanitizer] = {}
                for source in sources:
                    self.sanitized_variables[sanitizer][source] = [] 
                    self.sanitized_paths[sanitizer][source] = []          

            self.unsanitized_flows[True] = []
            self.unsanitized_flows[False] = []

            self.tainted_vars_in_test = []

        def get_tainted_variables(self):
            return self.tainted_variables

        def get_tainted_paths(self):
            return self.tainted_paths

        def get_instantiated_variables(self):
            return self.instantiated_variables

        def get_sanitized_variables(self):
            return self.sanitized_variables
        
        def get_sanitized_paths(self):
            return self.sanitized_paths
        
        def get_unsanitized_flows(self):
            return self.unsanitized_flows
        
        def get_tainted_vars_in_test(self):
            return self.tainted_vars_in_test

        def equals(self, other_state):

            def are_dicts_equal(dict1, dict2):
                if dict1.keys() != dict2.keys():
                    return False
                
                for key in dict1.keys():
                    if collections.Counter(dict1[key]) != collections.Counter(dict2[key]):
                        return False
                
                return True
            
            def are_sanitization_dicts_equal(dict1, dict2):
                if dict1.keys() != dict2.keys():
                    return False
                
                for key in dict1.keys():
                    if not are_dicts_equal(key, dict2[key]):
                        return False
                
                return True
                

            return are_dicts_equal(self.tainted_variables, other_state.tainted_variables) and \
                    are_dicts_equal(self.tainted_paths, other_state.tainted_paths) and \
                    collections.Counter(self.instantiated_variables) == collections.Counter(other_state.instantiated_variables) and \
                    are_sanitization_dicts_equal(self.sanitized_variables, other_state.sanitized_variables) and \
                    are_sanitization_dicts_equal(self.sanitized_paths, other_state.sanitized_paths) and \
                    are_sanitization_dicts_equal(self.unsanitized_flows, other_state.unsanitized_flows)
                    

    def traverseAST(sinks, state, node, implicit_body, flow_target, sanitizers_in_use):

        tainted_variables = state.get_tainted_variables()
        tainted_paths = state.get_tainted_paths()
        instantiated_variables = state.get_instantiated_variables()

        sanitized_variables = state.get_sanitized_variables()
        sanitized_paths = state.get_sanitized_paths()
        unsanitized_flows = state.get_unsanitized_flows()

        tainted_vars_in_test = state.get_tainted_vars_in_test()

        if node['ast_type'] == 'Assign':
            for target in node['targets']:
                flow_target.append(target['id'])
                if target['id'] not in tainted_vars_in_test: #for variables in test that were not initialized previously
                    instantiated_variables.append(target['id'])
            traverseAST(sinks, state, node['value'], implicit_body, flow_target, sanitizers_in_use)

        elif node['ast_type'] == 'Call':
            instantiated_variables.append(node['func']['id'])

            flow_target.append(node['func']['id'])
            for argument in node['args']:
                if node['func']['id'] in sanitizers: 
                    sanitizers_in_use.append(node['func']['id'])
                traverseAST(sinks, state, argument, implicit_body, flow_target, sanitizers_in_use)
                if node['func']['id'] in sanitizers_in_use:
                    sanitizers_in_use.remove(node['func']['id']) #after traversing through arguments
                if argument in flow_target:
                    flow_target.remove(argument) #to prevent other arguments from reading functions as arguments

            traverseAST(sinks, state, node['func'], implicit_body, flow_target, sanitizers_in_use)
            if node['func']['id'] in flow_target:
                flow_target.remove(node['func']['id'])

        elif node['ast_type'] == 'BinOp':
            traverseAST(sinks, state, node['left'], implicit_body, flow_target, sanitizers_in_use)
            traverseAST(sinks, state, node['right'], implicit_body, flow_target, sanitizers_in_use)

        elif node['ast_type'] == 'Expr':
            traverseAST(sinks, state, node['value'], implicit_body, flow_target, sanitizers_in_use)

        elif node['ast_type'] == 'Compare':
            for comparator in node['comparators']:
                traverseAST(sinks, state, node[comparator], implicit_body, flow_target, sanitizers_in_use)
                
        elif node['ast_type'] == 'Attribute':

            if node['attr'] in sources:

                for flow in flow_target:

                    if flow in sinks:

                        tainted_paths[node['attr']].append(flow)

                    else:

                        tainted_variables[node['attr']].append(flow)

            for key,val in tainted_variables.items():

                if node['attr'] in val:

                    for flow in flow_target:

                        if flow in sinks:

                            tainted_paths[key].append(flow)

                        else:

                            tainted_variables[key].append(flow)

            traverseAST(sinks, state, node['value'], implicit_body, flow_target, sanitizers_in_use)

        elif node['ast_type'] == 'Constant':
            pass
        elif node['ast_type'] == 'Name':

            #only if implicit = yes
            if implicit_body == True:
                for var in tainted_vars_in_test:
                    for key, val in tainted_variables.items(): #if variable in test is tainted
                        if var in val:
                            if node['id'] not in tainted_variables[key]:
                                if node['id'] not in sanitizers:
                                    tainted_variables[key].append(node['id'])
                                    for sanitizer in sanitizers:
                                        if var in sanitized_variables[sanitizer][key]:
                                            sanitized_variables[sanitizer][key].append(node['id']) #append to sanitizers if variable in test is sanitized
                                    
                    
                    if var in sources or var not in instantiated_variables: #if variable in test is a source
                        if node['id'] not in tainted_variables[var]:
                            if node['id'] not in sanitizers:
                                tainted_variables[var].append(node['id'])
                                for sanitizer in sanitizers:
                                    if var in sanitized_variables[sanitizer][key]:
                                        sanitized_variables[sanitizer][key].append(node['id'])

            if node['id'] not in instantiated_variables and node['id'] not in tainted_variables.keys(): #add new entry point if variable is not initialized
                tainted_variables[node['id']] = [] 
                tainted_paths[node['id']] = []
                for sanitizer in sanitizers:
                    state.sanitized_paths[sanitizer][node['id']] = []
                    state.sanitized_variables[sanitizer][node['id']] = []

            if node['id'] in sources or node['id'] not in instantiated_variables: 
                
                #source taints a variable
                i = len(flow_target) - 1
                found_sanitizer = ""

                #iterate through flow_target from right to left
                while i >= 0:

                    if found_sanitizer != "": #these variables will be affected by current sanitizer in use

                        if flow_target[i] not in tainted_variables[node['id']] and flow_target[i] != node['id'] and flow_target[i] not in sanitizers: #since sources can be added to flow_target we have to make sure that they do not add themselves to their respective structures
                            if flow_target[i] not in sanitizers:
                                tainted_variables[node['id']].append(flow_target[i]) 
                        if flow_target[i] not in sanitized_variables[found_sanitizer][node['id']]:
                            sanitized_variables[found_sanitizer][node['id']].append(flow_target[i])

                        if (flow_target[i] in sinks or flow_target[i] in sanitizers) and flow_target[i] not in sanitized_paths[found_sanitizer][node['id']] and flow_target[i] != node['id']:
                            sanitized_paths[found_sanitizer][node['id']].append(flow_target[i]) #also adds sanitizers because there might be cases where one sanitizer is argument to other sanitizer
                            if flow_target[i] not in sanitized_variables[found_sanitizer][node['id']]:
                                sanitized_variables[found_sanitizer][node['id']].append(flow_target[i])
                            if {node['id']: flow_target[i]} not in unsanitized_flows[True] and {node['id']: flow_target[i]} not in unsanitized_flows[False]:
                                unsanitized_flows[False].append({node['id']: flow_target[i]}) #temporary append (if it sees that there is an unsanitized flow for the pair source-sink anywhere in the code it will change to True -> cannot change back to False)

                        if flow_target[i] in sinks and flow_target[i] not in tainted_paths[node['id']] and flow_target[i] != node['id']:
                            tainted_paths[node['id']].append(flow_target[i])
                            if {node['id']: flow_target[i]} not in unsanitized_flows[True] and {node['id']: flow_target[i]} not in unsanitized_flows[False]:
                                unsanitized_flows[True].append({key: flow_target[i]})

                            if {node['id']: flow_target[i]} in unsanitized_flows[False] and flow_target[i] not in sanitized_variables[found_sanitizer][node['id']] and flow_target[i] not in sanitized_paths[found_sanitizer][node['id']]:
                                unsanitized_flows[True].append({node['id']: flow_target[i]}) #change to True if it finds at least one case of an unsanitized flow for the pair source-sink
                                unsanitized_flows[False].remove({node['id']: flow_target[i]})
                        
                    if len(sanitizers_in_use) > 0: #update the sanitizer that will sanitize variables to its left on flow_target
                        if flow_target[i] == sanitizers_in_use[len(sanitizers_in_use) - 1]:
                            found_sanitizer = flow_target[i]

                    if found_sanitizer == "": #these variables will NOT be affected by current sanitizer in use
                        if flow_target[i] not in tainted_variables[node['id']] and flow_target[i] != node['id']:
                            if flow_target[i] not in sanitizers:
                                tainted_variables[node['id']].append(flow_target[i])
                        for sanitizer in sanitized_variables.keys():
                            if flow_target[i] in sanitized_variables[sanitizer][node['id']]:
                                sanitized_variables[sanitizer][node['id']].remove(flow_target[i]) #if the variable was previously sanitized (regarding this source)
                        if flow_target[i] in sinks and flow_target[i] != node['id']:
                            for sanitizer in sanitized_variables.keys():
                                if flow_target[i] not in sanitized_paths[sanitizer][node['id']] and node['id'] in sanitized_variables[sanitizer][node['id']]: 
                                    sanitized_paths[sanitizer][node['id']].append(flow_target[i])
                                    
                            if flow_target[i] not in tainted_paths[node['id']]:
                                tainted_paths[node['id']].append(flow_target[i])
                                
                            #since a source cannot be sanitized, there will be at least one unsanitized flow so the pair cannot go to False
                            if {node['id']: flow_target[i]} in unsanitized_flows[False]:
                                unsanitized_flows[True].append({node['id']: flow_target[i]})
                                unsanitized_flows[False].remove({node['id']: flow_target[i]})
                                        
                            if {node['id']: flow_target[i]} not in unsanitized_flows[True] and {node['id']: flow_target[i]} not in unsanitized_flows[False]:
                                unsanitized_flows[True].append({node['id']: flow_target[i]})

                        
                    i -= 1

            #tainted variable taints a variable
            for key, val in tainted_variables.items():

                if node['id'] in val:
                    i = len(flow_target) - 1
                    found_sanitizer = ""

                    #iterate through flow_target from right to left
                    while i >= 0:

                        if found_sanitizer != "": #these variables will be affected by current sanitizer in use

                            if flow_target[i] not in tainted_variables[key] and flow_target[i] != node['id'] and flow_target[i] not in sanitizers:
                                if flow_target[i] not in sanitizers:
                                    tainted_variables[key].append(flow_target[i]) 

                            if flow_target[i] not in sanitized_variables[found_sanitizer][key]:
                                sanitized_variables[found_sanitizer][key].append(flow_target[i])

                            if (flow_target[i] in sinks or flow_target[i] in sanitizers) and flow_target[i] not in sanitized_paths[found_sanitizer][key]:
                                sanitized_paths[found_sanitizer][key].append(flow_target[i])
                                if flow_target[i] not in sanitized_variables[found_sanitizer][key]:
                                    sanitized_variables[found_sanitizer][key].append(flow_target[i])
                                if {key: flow_target[i]} not in unsanitized_flows[True] and {key: flow_target[i]} not in unsanitized_flows[False] and flow_target[i] not in sanitizers:
                                    unsanitized_flows[False].append({key: flow_target[i]})

                            if flow_target[i] in sinks and flow_target[i] not in tainted_paths[key] and flow_target[i] != node['id']:
                                tainted_paths[key].append(flow_target[i])
                                if {key: flow_target[i]} not in unsanitized_flows[True] and {key: flow_target[i]} not in unsanitized_flows[False]:
                                    unsanitized_flows[True].append({key: flow_target[i]})

                                if {key: flow_target[i]} in unsanitized_flows[False] and flow_target[i] not in sanitized_variables[found_sanitizer][key]:
                                    unsanitized_flows[True].append({key: flow_target[i]})
                                    unsanitized_flows[False].remove({key: flow_target[i]})
                              
                            
                        if len(sanitizers_in_use) > 0: #update the sanitizer that will sanitize variables to its left on flow_target 
                            if flow_target[i] == sanitizers_in_use[len(sanitizers_in_use) - 1]:
                                found_sanitizer = flow_target[i]

                        if found_sanitizer == "": #these variables will NOT be affected by current sanitizer in use

                            if flow_target[i] not in tainted_variables[key] and flow_target[i] != node['id']:
                                if flow_target[i] not in sanitizers:
                                    tainted_variables[key].append(flow_target[i])

                            for sanitizer in sanitizers:
                                if node['id'] in sanitized_variables[sanitizer][key] and flow_target[i] not in sanitized_variables[sanitizer][key]:
                                    sanitized_variables[sanitizer][key].append(flow_target[i])
                            
                            if flow_target[i] in sinks and flow_target[i] != node['id']:
                                if flow_target[i] not in tainted_paths[key]:
                                    tainted_paths[key].append(flow_target[i])

                                if len(sanitizers) > 0:
                                    for sanitizer in sanitized_variables.keys():
                                        if node['id'] in sanitized_variables[sanitizer][key]: #if the variable that "taints" the other is sanitized
                                            if flow_target[i] not in sanitized_paths[sanitizer][key]:
                                                sanitized_paths[sanitizer][key].append(flow_target[i])
                                                if flow_target[i] not in sanitized_variables[sanitizer][key]:
                                                    sanitized_variables[sanitizer][key].append(flow_target[i])
                                            if {key: flow_target[i]} not in unsanitized_flows[True] and {key: flow_target[i]} not in unsanitized_flows[False]:
                                                unsanitized_flows[False].append({key: flow_target[i]})

                                        if node['id'] not in sanitized_variables[sanitizer][key] and flow_target[i] in sanitized_variables[sanitizer][key]: #if the variable that "taints" the other (sanitized) is not sanitized
                                            sanitized_variables[sanitizer][key].remove(flow_target[i])
                                            if {key: flow_target[i]} not in unsanitized_flows[True]:
                                                unsanitized_flows[True].append({key: flow_target[i]})
                                            if {key: flow_target[i]} in unsanitized_flows[False]:
                                                unsanitized_flows[False].remove({key: flow_target[i]})
                                if {key: flow_target[i]} not in unsanitized_flows[True] and {key: flow_target[i]} not in unsanitized_flows[False]: #otherwise
                                    unsanitized_flows[True].append({key: flow_target[i]})
                            for sanitizer in sanitized_variables.keys():
                                if flow_target[i] in sanitized_variables[sanitizer][key] and node['id'] not in sanitized_variables[sanitizer][key]:
                                    sanitized_variables[sanitizer][key].remove(flow_target[i]) #if the varaible is tainted again
                        i -= 1


    def analyse_body(body, integrity_states, sinks, implicit):

        def register_implicit_sources(test_section, integrity_states):

            def traverse_test_body(test_section, vars_in_test):

                if test_section['ast_type'] == 'Compare':

                    for comparator in test_section['comparators']:
                        traverse_test_body(comparator, vars_in_test)

                    traverse_test_body(test_section['left'], vars_in_test)


                elif test_section['ast_type'] == 'Call':

                    for argument in test_section['args']:
                        traverse_test_body(argument, vars_in_test)

                    traverse_test_body(test_section['func'], vars_in_test)


                elif test_section['ast_type'] == 'BinOp':

                    traverse_test_body(test_section['left'], vars_in_test)
                    traverse_test_body(test_section['right'], vars_in_test)


                elif test_section['ast_type'] == 'Constant':

                    pass

                
                elif test_section['ast_type'] == 'Name':
                    vars_in_test.append(test_section['id'])


            vars_in_test = []
            traverse_test_body(test_section, vars_in_test)


            for state in integrity_states:
                for var in vars_in_test:
                    if var not in sources and var not in state.get_instantiated_variables():
                        state.tainted_variables[var] = [] 
                        state.tainted_paths[var] = []
                        for sanitizer in sanitizers:
                            state.sanitized_paths[sanitizer][var] = []
                            state.sanitized_variables[sanitizer][var] = []
                        if var not in state.get_tainted_vars_in_test():
                            state.get_tainted_vars_in_test().append(var)
                    if var in sources:
                        if var not in state.get_tainted_vars_in_test():
                            state.get_tainted_vars_in_test().append(var)
                    for key, val in state.get_tainted_variables().items():
                        if var in val:
                            if var not in state.get_tainted_vars_in_test():
                                state.get_tainted_vars_in_test().append(var)
        
        for body_section in body:

            if body_section['ast_type'] == 'If':
                
                if implicit == "yes":
                    register_implicit_sources(body_section['test'], integrity_states)
                
                integrity_states_copy = copy.deepcopy(integrity_states)

                new_states = analyse_body(body_section['body'], integrity_states_copy, sinks, implicit)
                
                #Recursively analyse elifs and else, in case they exist
                if body_section['orelse']:

                    orelse_body_section = body_section['orelse'][0]

                    while orelse_body_section['ast_type'] == 'If':

                        if implicit == "yes":
                            register_implicit_sources(orelse_body_section['test'], integrity_states)
                        
                        integrity_states_copy = copy.deepcopy(integrity_states)

                        new_states += analyse_body(orelse_body_section['body'], integrity_states_copy, sinks, implicit)
                        
                        if(orelse_body_section['orelse']):
                            orelse_body_section = orelse_body_section['orelse'][0]
            
                    #Analyse "else" body
                    for state in integrity_states:
                        traverseAST(sinks, state, orelse_body_section, "REMOVER", [], [])

                
                if implicit == "yes":
                    for state in integrity_states:
                        state.tainted_vars_in_test = []

                integrity_states += new_states


            elif body_section['ast_type'] == 'While':
                
                if implicit == "yes":
                    register_implicit_sources(body_section['test'], integrity_states)

                new_states = []

                initial_states = copy.deepcopy(integrity_states)
                filtered_states = []

                for i in range(5):

                    end_states = analyse_body(body_section['body'], copy.deepcopy(initial_states), sinks, implicit)
                    
                    filtered_states = []
                    for end_state in end_states:

                        redundant_state = False

                        for initial_state in initial_states:
                            if end_state.equals(initial_state):
                                redundant_state = True

                        if not redundant_state:
                            filtered_states.append(end_state)

                    new_states += filtered_states

                    initial_states = filtered_states


                if implicit == "yes":
                    for state in integrity_states:
                        state.tainted_vars_in_test = []
                 
                integrity_states += new_states

            else:

                for state in integrity_states:
                    traverseAST(sinks, state, body_section, True, [], [])
        
        return integrity_states


    def register_vulns(vuln_name, sanitizers, integrity_states):

        same_pattern_vulns = 1
        for state in integrity_states:
            for src, snks in state.get_tainted_paths().items():
  
                for snk in snks:
                    duplicate = 0

                    vuln = {}
                    vuln["vulnerability"] = vuln_name + "_" + str(same_pattern_vulns)
                    vuln["source"] = str(src)
                    vuln["sink"] = str(snk)

                    vuln["unsanitized flows"] = "no"
                    if {vuln["source"]: vuln["sink"]} in state.get_unsanitized_flows()[True]:
                        vuln["unsanitized flows"] = "yes"

                    vuln["sanitized flows"] = []
                    for sanitizer in state.get_sanitized_paths():
                        
                        if vuln["sink"] in state.get_sanitized_paths()[sanitizer][vuln["source"]]:
                            aux = [sanitizer]

                            if aux not in vuln["sanitized flows"]:
                                vuln["sanitized flows"].append(aux)

                            for var in state.get_sanitized_paths()[sanitizer][vuln["source"]]:
                                if var in sanitizers:
                                    aux.append(var)

                            aux.sort()
                            if aux not in vuln["sanitized flows"]:
                                vuln["sanitized flows"].append(aux)

                    for found in found_vulns:
                        if found["source"] == vuln["source"] and found["sink"] == vuln["sink"] and found["vulnerability"][0] == vuln["vulnerability"][0]:
                            for sanitizer in vuln["sanitized flows"]:
                                if sanitizer not in found["sanitized flows"]:
                                    found["sanitized flows"].append(sanitizer)
                            if vuln["unsanitized flows"] == "yes":
                                found["unsanitized flows"] = "yes"
                            duplicate = 1

                    if duplicate == 0 or len(found_vulns) == 0:
                        max_vuln_number = 0
                        for found in found_vulns:
                            if found["vulnerability"][0] == vuln["vulnerability"][0]:
                                max_vuln_number = max(max_vuln_number, int(found["vulnerability"][2:]))

                        vuln["vulnerability"] = vuln_name + "_" + str(max_vuln_number + 1)

                        found_vulns.append(vuln)

                    same_pattern_vulns += 1


    
    integrity_states = analyse_body(programAST['body'], [IntegrityState(sources, sanitizers),], sinks, implicit)

    register_vulns(vuln_name, sanitizers, integrity_states)

    

programFileName = sys.argv[1]
patternFileName = sys.argv[2]

with open(programFileName, 'r') as f:
    programAST = json.loads(f.read())
    print("[DEBUG] Loaded program file.")

with open(patternFileName, "r") as f:
    patternAST = json.loads(f.read())
    print("[DEBUG] Loaded pattern file.")

analysisOutput =  open(programFileName.split(".")[0] + ".output.json", "w")
print("[DEBUG] Loaded output file.")

for pattern in patternAST:
    print("[DEBUG] " + str(pattern))
    find_vulnerabilities(pattern['vulnerability'], pattern['sources'], pattern['sanitizers'], pattern['sinks'], pattern['implicit'])

print(found_vulns)
analysisOutput.write(str(found_vulns))
analysisOutput.close()