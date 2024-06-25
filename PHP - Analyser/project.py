def traverse_ast(ast1, sources1, sanitizers1, sinks1, implicit1, vulnerability):
    global ast
    global sources
    global sanitizers
    global sinks
    global implicit
    global variables
    global pairs
    global ifs
    global ifs_branches
    global implicit_dependencies

    ast = ast1
    sources = sources1
    sanitizers = sanitizers1
    sinks = sinks1
    implicit = implicit1
    implicit_dependencies = []
    variables = []
    pairs = []
    flow = {}
    variables.append(flow)
    ifs = []
    ifs_branches = []

    for line in ast:
        if len(ifs) == 0:
            analyse_flow(line, list(variables))
        else:
            analyse_flow(line, list(ifs[-1][ifs_branches[-1]]))

    return build_output(vulnerability, pairs)


def analyse_flow(line, flows):
    aditional_flows = []
    for flow in flows:
        nodeType = line['nodeType']
        if line['nodeType'] == 'Stmt_Expression':
            l = line['expr']
            nodeType = l['nodeType']
            if nodeType == 'Expr_Assign' or nodeType.startswith('Expr_AssignOp'):
                name = '${}'.format(l['var']['name'])
                flow[name] = analyse_assign(l['expr'], name, flow)
                if name in sources:
                    flow[name].append(name)
            elif nodeType == 'Expr_FuncCall':
                analyse_func(l['args'], l['name']['parts'][0], flow)
            elif nodeType.startswith('Expr_BinaryOp'):
                analyse_bin_op(l, flow)

        elif nodeType == 'Stmt_Echo':
            objects = line['exprs']
            for obj in objects:
                nodetype = obj['nodeType']
                if nodetype.startswith('Expr_BinaryOp'):
                    analyse_bin_op(obj, flow)
                elif nodeType == 'Expr_FuncCall':
                    analyse_func(obj['args'], obj['name']['parts'][0], flow)

        elif nodeType == 'Stmt_If':
            dependencies = False
            if implicit == 'yes':
                dependencies = analyse_condition(line['cond'], flow)
            aux_flow = dict(flow)
            ifs_branches.append(0)
            list_if = [[variables.index(flow)]]
            ifs.append(list_if)
            aux_list = [flow]
            for expr in line['stmts']:
                aux_list = analyse_flow(expr, aux_list)  # Analyse the flow, and add possible new flows

            for elseif in line['elseifs']:
                aditional_flows.extend(analyse_if_block(elseif['stmts'], list_if, aux_flow))

            if line['else'] is not None:
                aditional_flows.extend(analyse_if_block(line['else']['stmts'], list_if, aux_flow))
            else:
                new_flow = dict(aux_flow)
                aditional_flows.append(new_flow)
                variables.append(new_flow)

            ifs_branches.pop()
            current_if = ifs.pop()
            if len(ifs) > 0:
                current_flows = ifs[-1][ifs_branches[-1]]
                for branch in current_if:
                    for f in branch:
                        if f not in current_flows:
                            current_flows.append(f)
            if dependencies:
                implicit_dependencies.pop()

        elif nodeType == 'Stmt_While':
            dependencies = False
            if implicit == 'yes':
                dependencies = analyse_condition(line['cond'], flow)
            aux_flow = dict(flow)
            aux_list = [flow]
            for expr in line['stmts']:
                aux_list = analyse_flow(expr, aux_list)  # Analyse the flow, and add possible new flows
            while_flows = aux_list

            while len(while_flows) > 0:
                for wh_flow in while_flows:
                    copy_flow = dict(wh_flow)
                    variables.append(copy_flow)
                    aux_list = [copy_flow]
                    for expr in line['stmts']:
                        aux_list = analyse_flow(expr, aux_list)  # Analyse the flow, and add possible new flows
                    for new_flow in aux_list:
                        if not new_flow.__eq__(wh_flow):
                            aditional_flows.append(new_flow)
                            while_flows.append(new_flow)
                        else:
                            if new_flow in variables:
                                variables.remove(new_flow)
                    while_flows.remove(wh_flow)
            aditional_flows.append(aux_flow)
            variables.append(aux_flow)
            if dependencies:
                implicit_dependencies.pop()

    for flow in aditional_flows:
        flows.append(flow)
    return flows


def analyse_condition(condition, flow):
    left = condition['left']
    right = condition['right']
    dependencies = []
    if left['nodeType'] == 'Expr_Variable':
        name = '${}'.format(left['name'])
        if name in sources:
            dependencies.append(name)
        elif name in flow:
            if len(flow[name]):
                dependencies.append(name)
        elif name not in sinks and name not in sanitizers:
            sources.append(name)
            dependencies.append(name)
    if right['nodeType'] == 'Expr_Variable':
        name = '${}'.format(right['name'])
        if name in sources:
            dependencies.append(name)
        elif name in flow:
            dependencies.extend(flow[name])
        elif name not in sinks and name not in sanitizers:
            sources.append(name)
            dependencies.append(name)
    if len(dependencies) == 0:
        return False
    implicit_dependencies.extend(dependencies)
    return True


def analyse_if_block(statements, list_if, aux_flow):
    aditional_flows = []
    ifs_branches[-1] += 1
    list_if.append([len(variables)])
    new_flow = dict(aux_flow)
    aditional_flows.append(new_flow)
    variables.append(new_flow)
    aux_list = [new_flow]
    for expr in statements:
        aux_list = analyse_flow(expr, aux_list)
    return aditional_flows


def analyse_assign(slice, variable_name, flow):
    status = []
    dependencies = []
    for dependencie in implicit_dependencies:
        if dependencie in flow:
            for d in flow[dependencie]:
                if d not in dependencies:
                    dependencies.append(d)
        else:
            dependencies.append(dependencie)
    if slice['nodeType'] == 'Expr_FuncCall':
        name = slice['name']['parts'][0]
        result = analyse_func(slice["args"], name, flow)
        if len(result) > 0:
            for r in result:
                if r not in status:
                    status.append(r)
    elif slice['nodeType'].startswith('Expr_BinaryOp'):
        status.extend(analyse_bin_op(slice, flow))

    elif slice['nodeType'] == 'Expr_ArrayDimFetch':
        status.append(slice['var']['name'])

    elif slice['nodeType'] == 'Scalar_String':
        return list(dependencies)
    elif slice['nodeType'] == 'Expr_Variable':
        name = '${}'.format(slice['name'])
        if name in flow:
            status = flow[name]
        elif name in sources:
            status = [name]
        elif name not in sinks:
            sources.append(name)
            status = [name]

    if len(dependencies) > 0:
        for dependencie in dependencies:
            if dependencie not in status:
                status.append(dependencie)

    if variable_name in sinks:
        for value in status:
            if isinstance(value, list):
                dic = {'source': value[-1], 'sink': variable_name, 'sanitizers': list(value[:-1])}
                pairs.append(dic)
            else:
                dic = {'source': value, 'sink': variable_name, 'sanitizers': []}
                pairs.append(dic)
    return status


def analyse_bin_op(slice, flow):
    status = []

    for arg in slice:
        if arg == 'left' or arg == 'right':
            if slice[arg]['nodeType'] == 'Expr_FuncCall':
                status.extend(analyse_func(slice[arg]['args'], slice[arg]['name']['parts'][0], flow))
            elif slice[arg]['nodeType'] == 'Expr_Variable':
                try:
                    status.extend(flow['${}'.format(slice[arg]['name'])])
                except KeyError:
                    sources.append('${}'.format(slice[arg]['name']))
                    status.append('${}'.format(slice[arg]['name']))
            elif slice[arg]['nodeType'].startswith('Expr_BinaryOp'):
                status.extend(analyse_bin_op(slice[arg], flow))

    return status


def analyse_func(args, name, flow):
    status = []
    for arg in args:
        if arg['value']['nodeType'] == 'Expr_FuncCall':
            status.extend(analyse_func(arg['value']['args'], arg['value']['name']['parts'][0], flow))
        elif arg['value']['nodeType'] == 'Expr_Variable':
            try:
                status.extend(flow['${}'.format(arg['value']['name'])])
            except KeyError:
                sources.append('${}'.format(arg['value']['name']))
                status.append('${}'.format(arg['value']['name']))
        elif arg['value']['nodeType'].startswith('Expr_BinaryOp'):
            status.extend(analyse_bin_op(arg['value'], flow))
        elif arg['value']['nodeType'] == 'Expr_ArrayDimFetch':
            status.append(arg['value']['var']['name'])

    if name in sources:
        if len(status) >= 1 and status[-1] != name:
            status.append(name)
        elif len(status) >= 2 and status[-2] in sanitizers:
            status.append(name)
        elif len(status) == 0:
            status.append(name)
    if name in sanitizers:
        final_status = []
        aux = [name]
        for value in status:
            if isinstance(value, list):
                if name in value:
                    aux = []
                aux.extend(value)
            else:
                aux.append(value)
            if aux not in final_status:
                final_status.append(list(aux))
            aux = [name]
        status = final_status
    elif name in sinks:
        for value in status:
            if isinstance(value, list):
                dic = {'source': value[-1], 'sink': name, 'sanitizers': list(value[:-1])}
                pairs.append(dic)
            else:
                dic = {'source': value, 'sink': name, 'sanitizers': []}
                pairs.append(dic)
    return status


def build_output(name, pairs):
    pair_list = []
    for pair in pairs:
        source = pair["source"]
        sink = pair["sink"]
        sanitizers = pair["sanitizers"]

        # Check if pair if doesn't exist
        if not any(curr_pair['source'] == source and curr_pair['sink'] == sink for curr_pair in pair_list):
            found_pair = {
                "vulnerability": name,
                "source": source,
                "sink": sink,
                "unsanitized flows": "no",
                "sanitized flows": []
            }
            pair_list.append(found_pair)
        # Check what value to edit
        index = -1
        for i, curr_pair in enumerate(pair_list):
            if curr_pair['source'] == source and curr_pair['sink'] == sink:
                index = i
                break
        if not any(
                sanitizers == sanitized_flow for sanitized_flow in found_pair['sanitized flows']) and sanitizers != []:
            pair_list[index]['sanitized flows'].append(sanitizers)
        if not sanitizers:
            pair_list[index]['unsanitized flows'] = "yes"

    return pair_list
