import ast
from Policy import Policy
from MultiLabel import MultiLabel
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities
import traverses_op
import inspect

#######################
# Expression Handlers #
######################

# Simple dispatcher for expression evaluation

def traverse_Name(node: ast.Name, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Name nodes.
    """
    # Return the multilabel associated with this variable name
    
    try:
        multilabel = multiLabelling.get_multilabel(node.id)
        return multilabel
    except KeyError:
        # Handle the case where the variable name does not exist
        return MultiLabel(policy.patterns)
    
def traverse_Call_inactive(node: ast.Call, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Call nodes.
    """
    
    # Implement logic for handling ast.Call nodes
    
    #  print(ast.dump(ast.parse('func(a, b=c, *d, **e)', mode='eval'), indent=4))
        # Expression(
        #     body=Call(
        #         func=Name(id='func', ctx=Load()),
        #         args=[
        #             Name(id='a', ctx=Load()),
        #             Starred(
        #                 value=Name(id='d', ctx=Load()),
        #                 ctx=Load())],
        #         keywords=[
        #             keyword(
        #                 arg='b',
        #                 value=Name(id='c', ctx=Load())),
        #             keyword(
        #                 value=Name(id='e', ctx=Load()))]))

    # Call(expr func, expr* args, keyword* keywords)
    """
        1. check if function is source for a vulnerability in patterns
        2. check if function is a sanitizer
        3. check if function is a sink 
        4. check if function has input variables that may be tainted
    """
    # TODO NO ATTRIBUTES CONSIDERED FOR NOW
    # Get function name
    func_name = None
    if isinstance(node.func, ast.Name):
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        func_name = node.func.attr

    combined_ml = MultiLabel(policy.patterns)
    # Evaluate function name
    func_ml = eval_expr(func_name, policy, multiLabelling, vulnerabilities)

    # check for illegal flows
    if func_name:
        illegal_flows_ml = policy.detect_illegal_flows(func_name, func_ml)
        if illegal_flows_ml:  # If there are illegal flows
            lineno = getattr(node, "lineno", None)
            vulnerabilities.add_vulnerability(func_name, illegal_flows_ml, lineno) 

    combined_ml = combined_ml.combinor(func_ml)
    # Evaluate positional arguments
    for arg in node.args:
        arg_ml = eval_expr(arg, policy, multiLabelling, vulnerabilities)
        combined_ml = combined_ml.combinor(arg_ml)

    return combined_ml


def traverse_Call(node: ast.Call, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    func_name = None
    if isinstance(node.func, ast.Name): # d()
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute): # modulo.attr()
        func_name = node.func.attr

    ml = MultiLabel(policy.patterns)

    if func_name:
        # Assignment context: x = func(args)
        if isinstance(parent, ast.Assign):
            lineno = getattr(node, "lineno", None)
            # Evaluate args and combine their multilabels
            for arg in node.args:
                arg_ml = eval_expr(arg, policy, multiLabelling, vulnerabilities)
                ml = ml.combinor(arg_ml)
            ml.add_source(func_name, lineno)
            ml.add_sanitizer_to_all(func_name, lineno)

        # Standalone call context: func(args)
        elif isinstance(parent, ast.Expr):
            # Check if it's a sink - detect illegal flows
            for arg in node.args:
                arg_ml = eval_expr(arg, policy, multiLabelling, vulnerabilities)
                ml = ml.combinor(arg_ml)
                illegal_multilabel = policy.detect_illegal_flows(func_name, ml)
                if illegal_multilabel:
                    lineno = getattr(node, "lineno", None)
                    vulnerabilities.add_vulnerability(func_name, ml, lineno)
                # Combine args
            #TODO: can sanitizers be called standalone? 

    return ml

def traverse_UnaryOp(node: ast.UnaryOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:
    """
    Handles traversal of ast.UnaryOp nodes.
    """
    
    # UnaryOp(unaryop op, expr operand)
    
    # Evaluate operand and return its multilabel (unary ops don't change labels)
    return eval_expr(node.operand, policy, multiLabelling, vulnerabilities)
    
    

def traverse_BoolOp(node: ast.BoolOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:
    """
    Handles traversal of ast.BoolOp nodes.
    """
    # BoolOp(boolop op, expr* values)
    # Implement logic for handling ast.BoolOp nodes
        
    combined_ml = MultiLabel(policy.patterns)
    for value in node.values:
        value_ml = eval_expr(value, policy, multiLabelling, vulnerabilities)
        combined_ml = combined_ml.combinor(value_ml)
        
    return combined_ml


def traverse_Constant(node: ast.Constant, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel: 
    """
    Handles traversal of ast.Constant nodes.
    """
    # Constants carry no sources; return an empty multilabel across patterns
    # Simplesmente criamos uma nova label
    return MultiLabel(policy.patterns)

def traverse_BinOp(node: ast.BinOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:
    """
    Handles traversal of ast.BinOp nodes.
    """    
    # Combine multilabels from left and right expressions
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities)
    right_ml = eval_expr(node.right, policy, multiLabelling, vulnerabilities)
    return left_ml.combinor(right_ml)

def traverse_Compare(node: ast.Compare, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:     
    """
    Handles traversal of ast.Compare nodes.
    """
    # Compare(expr left, cmpop* ops, expr* comparators)
    
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities)
    
    for comparator in node.comparators:
        comp_ml = eval_expr(comparator, policy, multiLabelling, vulnerabilities)
        left_ml = left_ml.combinor(comp_ml)

    return left_ml

def traverse_Attribute(node: ast.Attribute, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:
    """
    Handles traversal of ast.Attribute nodes. 
    """
    
    # Attribute(expr value, identifier attr, expr_context ctx)
    
    return eval_expr(node.value, policy, multiLabelling, vulnerabilities)
    
def traverse_Subscript(node: ast.Subscript, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:
    """
    Handles traversal of ast.Subscript nodes.
    """

    # Subscript(expr value, expr slice, expr_context ctx)
    
    # TODO handle slice properly ??????? PRECISAMOS DE OS AVALIAR? NOT SURE PROVAVELEMTNE SIM
    # VOU METER UMA VERSAO COM AVALIÇAO DAS SLICES MAS DESPOIS CONFIRMAR
    
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities)
    slice_ml = eval_expr(node.slice, policy, multiLabelling, vulnerabilities)
    return value_ml.combinor(slice_ml)
    
    
    
#######################
# Statement Handlers  #
######################

def traverse_Assign(node: ast.Assign, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabelling:
    """
    Handles traversal of ast.Assign nodes.
    """
        
    # Assign(expr* targets, expr value, string? type_comment)
    
    # print(ast.dump(ast.parse('a = b = 1'), indent=4)) # Multiple assignment
    #     Module(
    #         body=[
    #             Assign(
    #                 targets=[
    #                     Name(id='a', ctx=Store()),
    #                     Name(id='b', ctx=Store())],
    #                 value=Constant(value=1))])
    
    target = node.targets[0]
    
    # Only evaluate the value being assigned, not the target
    target_ml = eval_expr(target, policy, multiLabelling, vulnerabilities)
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent=node)
    
    combined_ml = value_ml.combinor(target_ml)
    
    # Update multilabelling for each target
    for target in node.targets:
        if isinstance(target, ast.Name):
            multiLabelling.mutator(target.id, combined_ml)

    return multiLabelling

def traverse_If(node: ast.If, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabelling:    
    """
    Handles traversal of ast.If nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.If nodes

def traverse_While(node: ast.While, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabelling:
    """
    Handles traversal of ast.While nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.While nodes

def traverse_Expr(node: ast.Expr, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabelling:
    """
    Handles traversal of ast.Expr nodes.
    """
    
    # Evaluate the expression (e.g., to detect sinks), but return the multiLabelling unchanged
    eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent=node)
    return multiLabelling
    


def eval_expr(node: ast.AST, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    EXPR_DISPATCH = {
        ast.Name: traverse_Name,
        ast.Constant: traverse_Constant,
        ast.UnaryOp: traverse_UnaryOp,
        ast.BinOp: traverse_BinOp,
        ast.BoolOp: traverse_BoolOp,
        ast.Call: traverse_Call,
        ast.Attribute: traverse_Attribute,
        ast.Subscript: traverse_Subscript,
        ast.Compare: traverse_Compare,
    }
    handler = EXPR_DISPATCH.get(type(node))
    if handler:
        # Check if the handler accepts a 'parent' parameter
        # this is needed because some expressions like Call need context to distinguish between:
        # Assignments: x = get_source() (creates a taint source)
        # Standalone calls: sink(x) (checks for vulnerabilities)
        handler_signature = inspect.signature(handler)
        if 'parent' in handler_signature.parameters:
            return handler(node, policy, multiLabelling, vulnerabilities, parent=parent)
        else:
            return handler(node, policy, multiLabelling, vulnerabilities)
    # Fallback: return an empty multilabel across policy patterns
    return MultiLabel(policy.patterns)


def traverse_stmt(node: ast.stmt, policy: Policy, multiLabelling: MultiLabelling, 
                  vulnerabilities: Vulnerabilities) -> MultiLabelling:
    """
    Traverses a statement node and returns updated multilabelling.
    This is the TOP LEVEL traversal that handles control flow.
    """
    if isinstance(node, ast.Assign):
        return traverse_Assign(node, policy, multiLabelling, vulnerabilities)
    elif isinstance(node, ast.If):
        return traverse_If(node, policy, multiLabelling, vulnerabilities)
    elif isinstance(node, ast.While):
        return traverse_While(node, policy, multiLabelling, vulnerabilities)
    elif isinstance(node, ast.Expr):
        return traverse_Expr(node, policy, multiLabelling, vulnerabilities)
    else:
        return multiLabelling
    

def logger(message: str, function_name: str = "") -> None:
    """
    Simple logger function for debugging.
    """
    print(f"[traverses_op] {function_name}: {message}")