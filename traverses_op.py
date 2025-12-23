import ast
from Policy import Policy
from MultiLabel import MultiLabel
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities
from Label import Label
import inspect

#######################
# Expression Handlers #
######################

# Simple dispatcher for expression evaluation

def traverse_Name(node: ast.Name, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    """
    Handles traversal of ast.Name nodes.
    """
    # Return the multilabel associated with this variable name
    
    try:
        multilabel = multiLabelling.get_multilabel(node.id)
        lineno = getattr(node, "lineno", None)

        for label in multilabel.labels.values():
            updated_flows = {}
            for src, sanitizers in label.flows.items():
                if src[0] == node.id and src[1] is None:
                    updated_flows[(src[0], lineno)] = sanitizers
                else:
                    updated_flows[src] = sanitizers
            
            # Replace the flows dict
            label.flows = updated_flows
        return multilabel
    except KeyError:
        # Handle the case where the variable name does not exist
        
        # check if it is a source or sanitizer function
        label = None
        for pattern in policy.patterns:
            if pattern.is_source(node.id):
                label = Label(flows={(node.id, None): set()})
                break

        if parent and isinstance(parent, ast.Call):
            lineno = getattr(node, "lineno", None)
            label = Label(flows={(node.id, lineno): set()})
            policy.add_pattern(node.id)

        return MultiLabel(policy.patterns, label = label)

def traverse_Call(node: ast.Call, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    func_name = None
    if isinstance(node.func, ast.Name): # d()
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute): # modulo.attr()
        func_name = node.func.attr

    ml = MultiLabel(policy.patterns)

    if func_name:
        lineno = getattr(node, "lineno", None)
        # Evaluate args and combine their multilabels
        for arg in node.args:
            arg_ml = eval_expr(arg, policy, multiLabelling, vulnerabilities, node)
            ml = ml.combinor(arg_ml)
            add_detect_illegal_flows(node, func_name, ml, policy, vulnerabilities, lineno)
        
        # Add as source if it's a source function
        ml.add_source(func_name, lineno)
        
        # Add as sanitizer only to existing flows from sources
        ml.add_sanitizer(func_name, lineno)    
    return ml

def traverse_UnaryOp(node: ast.UnaryOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    """
    Handles traversal of ast.UnaryOp nodes.
    """
    # UnaryOp(unaryop op, expr operand)
    # Simply evaluate the operand and return its multilabel
    return eval_expr(node.operand, policy, multiLabelling, vulnerabilities, parent)

def traverse_BoolOp(node: ast.BoolOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    """
    Handles traversal of ast.BoolOp nodes.
    """
    # BoolOp(boolop op, expr* values)
    # Implement logic for handling ast.BoolOp nodes
        
    combined_ml = MultiLabel(policy.patterns)
    for value in node.values:
        value_ml = eval_expr(value, policy, multiLabelling, vulnerabilities, parent)
        combined_ml = combined_ml.combinor(value_ml)
        
    return combined_ml


def traverse_Constant(node: ast.Constant, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel: 
    """
    Handles traversal of ast.Constant nodes.
    """
    # Constants carry no sources; return an empty multilabel across patterns
    # Simplesmente criamos uma nova label
    return MultiLabel(policy.patterns)

def traverse_BinOp(node: ast.BinOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    """
    Handles traversal of ast.BinOp nodes.
    """    
    # Combine multilabels from left and right expressions
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities, parent)
    right_ml = eval_expr(node.right, policy, multiLabelling, vulnerabilities, parent)
    
    combinored_ml = left_ml.combinor(right_ml)
    
    
    #check taint
    
    return combinored_ml

def traverse_Compare(node: ast.Compare, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:     
    """
    Handles traversal of ast.Compare nodes.
    """
    # Compare(expr left, cmpop* ops, expr* comparators)
    
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities, parent)
    
    for comparator in node.comparators:
        comp_ml = eval_expr(comparator, policy, multiLabelling, vulnerabilities, parent)
        left_ml = left_ml.combinor(comp_ml)

    return left_ml

def traverse_Attribute(node: ast.Attribute, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    """
    Handles traversal of ast.Attribute nodes. 
    """
    
    # Attribute(expr value, identifier attr, expr_context ctx)
    
    return eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent)
    
def traverse_Subscript(node: ast.Subscript, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None) -> MultiLabel:
    """
    Handles traversal of ast.Subscript nodes.
    """

    # Subscript(expr value, expr slice, expr_context ctx)
    
    # TODO handle slice properly ??????? PRECISAMOS DE OS AVALIAR? NOT SURE PROVAVELEMTNE SIM
    # VOU METER UMA VERSAO COM AVALIÇAO DAS SLICES MAS DESPOIS CONFIRMAR
    
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent)
    slice_ml = eval_expr(node.slice, policy, multiLabelling, vulnerabilities, parent)
    return value_ml.combinor(slice_ml)
    
    
    
#######################
# Statement Handlers  #
######################

def traverse_Assign(node: ast.Assign, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabelling:
    """
    Handles traversal of ast.Assign nodes.
    """
        
    # Assign(expr* targets, expr value, string? type_comment)
        
    target = node.targets[0]
    
    lineno = getattr(node, "lineno", None)
    
    # Only evaluate the value being assigned, not the target
    target_ml = eval_expr(target, policy, multiLabelling, vulnerabilities, node)
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities, node)
    
    combined_ml = value_ml.combinor(target_ml)
    
    # Update multilabelling for each target
    for target in node.targets:
        if isinstance(target, ast.Name):
            multiLabelling.mutator(target.id, combined_ml)
            logger(f"Assigned ML {combined_ml} to variable '{target.id}'", "traverse_Assign")
        
    add_detect_illegal_flows(node, target.id, combined_ml, policy, vulnerabilities, lineno)

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
            return handler(node, policy, multiLabelling, vulnerabilities, parent)
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
    

def logger(message: str, function_name: str = "", color: int = 1) -> None:
    """
    Simple logger function for debugging.
    """
    # print(f"[traverses_op] {function_name}:")
    # if color == 1:  # Green
    #     color = "\033[92m"
    # elif color == 2:  # Red
    #     color = "\033[91m"
    # color_end = "\033[0m"
    # print(f"{color}{message}{color_end}")

def add_detect_illegal_flows(node: ast.AST, func_name: str, ml: MultiLabel, policy: Policy, vulnerabilities: Vulnerabilities, lineno: int) -> MultiLabel:
    illegal_multilabel = policy.detect_illegal_flows(func_name, ml)
    if illegal_multilabel:
        lineno = getattr(node, "lineno", None)
        vulnerabilities.add_vulnerability(func_name, illegal_multilabel, lineno)
    return illegal_multilabel