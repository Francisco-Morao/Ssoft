import ast
from Policy import Policy
from MultiLabel import MultiLabel
from MultiLabelling import MultiLabelling
import ProgramCounter
from Vulnerabilities import Vulnerabilities
from Label import Label
import inspect

IS_IMPLICIT = True
IS_EXPLICIT = False

#######################
# Expression Handlers #
######################

# Simple dispatcher for expression evaluation
    
def traverse_Name(node: ast.Name, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    """
    Handles traversal of ast.Name nodes.
    """
    # Return the multilabel associated with this variable name
    
    try:
        multilabel = multiLabelling.get_multilabel(node.id)
        lineno = getattr(node, "lineno", None)

        # Create a new multilabel to avoid modifying the shared one
        new_multilabel = MultiLabel(set(multilabel.labels.keys()))
        
        for pattern, label in multilabel.labels.items():
            new_multilabel.labels[pattern] = label.copy_with_updated_lines(node.id, lineno)
            new_multilabel.set_implicit_flag(pattern, multilabel.get_implicit_flag(pattern))
        
        # Check if this variable name is also a source in the patterns
        for pattern in policy.patterns:
            if pattern.is_source(node.id):
                if pattern not in new_multilabel.labels:
                    new_multilabel.labels[pattern] = Label()
                    # Add as a new flow with no sanitizers
                    new_multilabel.labels[pattern].add_flow(node.id, lineno)
                else:
                    # Check if there's already a flow with this source name
                    label = new_multilabel.labels[pattern]
                    has_flow_with_source = False
                    for src, sanitizers in label.flows:
                        if src[0] == node.id:
                            has_flow_with_source = True
                            break
                    
                    if not has_flow_with_source:
                        # No existing flow with this source, add one
                        new_multilabel.labels[pattern].add_flow(node.id, lineno)
        
        return new_multilabel
    except KeyError:
        # Handle the case where the variable name does not exist
        # Undefined variables carry information that should be tracked conservatively
        lineno = getattr(node, "lineno", None)
        multilabel = MultiLabel(policy.patterns)
        
        # For undefined variables, create flows for ALL patterns
        # This is because accessing an undefined variable means we're reading unknown data
        for pattern in policy.patterns:
            multilabel.labels[pattern] = Label()
            multilabel.labels[pattern].add_flow(node.id, lineno)

        return multilabel  


def traverse_Call(node: ast.Call, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    
    func_name = None
    ml = MultiLabel(policy.patterns)
    
    if isinstance(node.func, ast.Name): # d()
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute): # b.m()
        func_name = node.func.attr
        # Evaluate the entire attribute access (b.m) to get flows from both the object and the attribute
        attr_ml = eval_expr(node.func, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
        ml = ml.combinor(attr_ml)
    
    if func_name is not None:
        lineno = getattr(node, "lineno", None)
        # Evaluate args and combine their multilabels
        for arg in node.args:
            arg_ml = eval_expr(arg, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
            ml = ml.combinor(arg_ml)
        
        # Add as source if it's a source function
        ml.add_source(func_name, lineno)
        
        # Add as sanitizer only to existing flows from sources
        ml.add_sanitizer(func_name, lineno)
        
        # Check for implicit flows from the program counter when calling a sink
        if not program_counter.is_empty():
            pc_ml = program_counter.multi_label()
            # Filter pc_ml to only include patterns with implicit flows enabled
            implicit_pc_ml = MultiLabel(set())
            for pattern, label in pc_ml.labels.items():
                if pattern.is_implicit_flow():
                    implicit_pc_ml.labels[pattern] = label
                    implicit_pc_ml.set_implicit_flag(pattern, IS_IMPLICIT)
            
            # Combine ml with PC for sink detection
            ml_with_pc = ml.combinor(implicit_pc_ml)
            # Detect implicit illegal flows with PC included
            add_detect_illegal_flows(node, func_name, ml_with_pc, policy, vulnerabilities, lineno)
        else:
            # Detect explicit illegal flows without PC
            add_detect_illegal_flows(node, func_name, ml, policy, vulnerabilities, lineno) 
    return ml

def traverse_UnaryOp(node: ast.UnaryOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    """
    Handles traversal of ast.UnaryOp nodes.
    """
    # Simply evaluate the operand and return its multilabel
    return eval_expr(node.operand, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)

def traverse_BoolOp(node: ast.BoolOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    """
    Handles traversal of ast.BoolOp nodes.
    """        
    combined_ml = MultiLabel(policy.patterns)
    for value in node.values:
        value_ml = eval_expr(value, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
        combined_ml = combined_ml.combinor(value_ml)
        
    return combined_ml


def traverse_Constant(node: ast.Constant, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel: 
    """
    Handles traversal of ast.Constant nodes.
    """
    # Constants carry no sources; return an empty multilabel across patterns
    # Simplesmente criamos uma nova label
    return MultiLabel(policy.patterns)

def traverse_BinOp(node: ast.BinOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    """
    Handles traversal of ast.BinOp nodes.
    """    
    # Combine multilabels from left and right expressions
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
    right_ml = eval_expr(node.right, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
    
    combinored_ml = left_ml.combinor(right_ml)

    return combinored_ml

def traverse_Compare(node: ast.Compare, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:     
    """
    Handles traversal of ast.Compare nodes.
    """    
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
    
    for comparator in node.comparators:
        comp_ml = eval_expr(comparator, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
        left_ml = left_ml.combinor(comp_ml)

    return left_ml

def traverse_Attribute(node: ast.Attribute, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    """
    Handles traversal of ast.Attribute nodes. 
    """
    
    # Get the multilabel from the base object
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
    
    lineno = getattr(node, "lineno", None)
    
    # The attribute name can be a source and we cant do the eval_expr because it is a string
    attr_ml = MultiLabel(policy.patterns)
    
    for pattern in policy.patterns:
        if pattern.is_source(node.attr):
            attr_ml.labels[pattern] = Label()
            attr_ml.labels[pattern].add_flow(node.attr, lineno)
    
    combined_ml = value_ml.combinor(attr_ml)
    
    return combined_ml
    
def traverse_Subscript(node: ast.Subscript, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
    """
    Handles traversal of ast.Subscript nodes.
    """

    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)
    slice_ml = eval_expr(node.slice, policy, multiLabelling, vulnerabilities, parent=parent, program_counter=program_counter)

    return value_ml.combinor(slice_ml)


#######################
# Statement Handlers  #
######################

def traverse_Assign(node: ast.Assign, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, program_counter: ProgramCounter) -> MultiLabelling:
    """
    Handles traversal of ast.Assign nodes.
    """

    target = node.targets[0]
    
    lineno = getattr(node, "lineno", None)
    target_id = None
    target_ml = eval_expr(target, policy, multiLabelling, vulnerabilities, parent=node, program_counter=program_counter)
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent=node, program_counter=program_counter)

    if isinstance(target, ast.Attribute):
        target_id = target.value.id
        target_attr = target.attr
        # Precisamos de confirmar o bloco do a.c = b
        # Ou seja se para do b há flow para o c 
        # depois mais a frente confirmar o a que é o value
        add_detect_illegal_flows(node, target_attr, value_ml, policy, vulnerabilities, lineno)
    elif isinstance(target, ast.Subscript):
        target_id = target.value.id
        # Precisamos de confirmar este bloco todo c[a] e depois mais a frente o value
        add_detect_illegal_flows(node, target_id, target_ml, policy, vulnerabilities, lineno)
    else:
        target_id = target.id
    
    # Detect explicit flows
    add_detect_illegal_flows(node, target_id, value_ml, policy, vulnerabilities, lineno)
    
    # Implicit flows from program counter
    if not program_counter.is_empty():
        pc_ml = program_counter.multi_label()
        # Filter pc_ml to only include patterns with implicit flows enabled
        implicit_pc_ml = MultiLabel(set())
        for pattern, label in pc_ml.labels.items():
            if pattern.is_implicit_flow():
                implicit_pc_ml.labels[pattern] = label
                implicit_pc_ml.set_implicit_flag(pattern, IS_IMPLICIT)
        
        # Detect implicit flows
        add_detect_illegal_flows(node, target_id, implicit_pc_ml, policy, vulnerabilities, lineno)
        
        # Combine for multilabelling update
        value_ml = value_ml.combinor(implicit_pc_ml)
    multiLabelling.mutator(target_id, value_ml)
    # tanto para atributos e subscripts
    # precisamos de combinar os multilabels porque queremos manter a informação que 
    # já estava no value do atributo ou subscript com o target que está a ser atribuído
    if isinstance(target, ast.Attribute) or isinstance(target, ast.Subscript):
        target_ml = target_ml.combinor(value_ml)
        multiLabelling.mutator(target_id, target_ml)

    return multiLabelling

def traverse_If(node: ast.If, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, program_counter: ProgramCounter) -> tuple[MultiLabelling, MultiLabelling]:
    """
    Handles traversal of ast.If nodes.
    """
    # For statements that introduce more than one control path, create copies of multilabellings
    # and combine them so as to capture correctly the different paths that information flows might
    # be taking

    # Evaluate the condition of the if statement
    
    condition_ml = eval_expr(node.test, policy, multiLabelling, vulnerabilities, parent=node, program_counter=program_counter)
    
    # if(condition) 
    program_counter.push(condition_ml)
    
    # Create a copy of the multilabelling for the "if" branch
    if_branch_labelling = multiLabelling.copy()

    # Traverse the code inside the if
    for stmt in node.body:
        stmt_labellings = traverse_stmt(stmt, policy, if_branch_labelling, vulnerabilities, program_counter=program_counter)
        for stmt_labelling in stmt_labellings:
            if_branch_labelling = if_branch_labelling.combinor(stmt_labelling)

    # Create a copy of the multilabelling for the "else" branch
    else_branch_labelling = multiLabelling.copy()
    for stmt in node.orelse:
        stmt_labellings = traverse_stmt(stmt, policy, else_branch_labelling, vulnerabilities, program_counter=program_counter)
        for stmt_labelling in stmt_labellings:
            else_branch_labelling = else_branch_labelling.combinor(stmt_labelling)

    program_counter.pop()

    return if_branch_labelling, else_branch_labelling

def traverse_While(node: ast.While, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, program_counter: ProgramCounter) -> tuple[MultiLabelling, MultiLabelling]:
    """
    Handles traversal of ast.While nodes.
    """

    # Evaluate the condition of the while loop
    not_entered_labelling = multiLabelling.copy()
    for stmt in node.orelse:
        stmt_labellings = traverse_stmt(stmt, policy, not_entered_labelling, vulnerabilities, program_counter)
        for stmt_labelling in stmt_labellings:
            not_entered_labelling = not_entered_labelling.combinor(stmt_labelling)
    
    # When the loop is entered and executed
    # Adjust unroll limit based on nested if statements
    # More nested ifs require more iterations to capture all paths
    nested_if_count = count_nested_ifs(node.body)
    UNROLL_LIMIT = 2 + nested_if_count  # Base of 2, plus 1 for each nested if
    
    current_labelling = multiLabelling.copy()
    
    # Accumulate all condition states across iterations to capture different sanitization paths
    accumulated_condition_ml = MultiLabel(policy.patterns)
    
    for _ in range(UNROLL_LIMIT):
        # Re-evaluate condition each iteration as variables may change
        condition_ml = eval_expr(node.test, policy, current_labelling, vulnerabilities, parent=node, program_counter=program_counter)
        # Accumulate this iteration's condition with previous iterations
        accumulated_condition_ml = accumulated_condition_ml.combinor(condition_ml)
        # Push the accumulated condition to capture all possible paths
        program_counter.push(accumulated_condition_ml)
        
        # Traverse the body of the while loop
        for stmt in node.body:
            stmt_labellings = traverse_stmt(stmt, policy, current_labelling, vulnerabilities, program_counter)
            for stmt_labelling in stmt_labellings:
                current_labelling = current_labelling.combinor(stmt_labelling)

        program_counter.pop()

    return [not_entered_labelling, current_labelling]


def traverse_Expr(node: ast.Expr, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, program_counter: ProgramCounter) -> MultiLabelling:
    """
    Handles traversal of ast.Expr nodes.
    """
    
    # Evaluate the expression (e.g., to detect sinks), but return the multiLabelling unchanged
    eval_expr(node.value, policy, multiLabelling, vulnerabilities, parent=node, program_counter=program_counter)
    return multiLabelling
    


def eval_expr(node: ast.AST, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities, parent: ast.AST = None, program_counter: ProgramCounter = None) -> MultiLabel:
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
            return handler(node, policy, multiLabelling, vulnerabilities, parent, program_counter)
        else:
            return handler(node, policy, multiLabelling, vulnerabilities, program_counter)
    # Fallback: return an empty multilabel across policy patterns
    return MultiLabel(policy.patterns)


def traverse_stmt(node: ast.stmt, policy: Policy, multiLabelling: MultiLabelling, 
                  vulnerabilities: Vulnerabilities, program_counter: ProgramCounter) -> list[MultiLabelling]:
    """
    Traverses a statement node and returns a list of updated multilabellings.
    This is the TOP LEVEL traversal that handles control flow.
    """
    if isinstance(node, ast.Assign):
        return [traverse_Assign(node, policy, multiLabelling, vulnerabilities, program_counter)]
    elif isinstance(node, ast.If):
        if_labelling, else_labelling = traverse_If(node, policy, multiLabelling, vulnerabilities, program_counter)
        return [if_labelling, else_labelling]
    elif isinstance(node, ast.While):
        return traverse_While(node, policy, multiLabelling, vulnerabilities, program_counter)
    elif isinstance(node, ast.Expr):
        return [traverse_Expr(node, policy, multiLabelling, vulnerabilities, program_counter)]
    else:
        return [multiLabelling]
    
#######################
# Helper Functions    #
#######################

def count_nested_ifs(node_body: list[ast.stmt]) -> int:
    """
    Counts the number of nested if statements in a list of statements.
    This helps determine how many loop unrolls are needed to capture all control flow paths.
    """
    count = 0
    for stmt in node_body:
        if isinstance(stmt, ast.If):
            count += 1
            # count nested ifs within the if/else branches
            count += count_nested_ifs(stmt.body)
            count += count_nested_ifs(stmt.orelse)
        elif isinstance(stmt, ast.While):
            count += count_nested_ifs(stmt.body)
    return count

def logger(message: str, function_name: str = "", color: int = 1) -> None:
    """
    Simple logger function for debugging.
    """
    print(f"[traverses_op] {function_name}:")
    if color == 1:  # Green
        color = "\033[92m"
    elif color == 2:  # Red
        color = "\033[91m"
    color_end = "\033[0m"
    print(f"{color}{message}{color_end}")

def add_detect_illegal_flows(node: ast.AST, func_name: str, ml: MultiLabel, policy: Policy, vulnerabilities: Vulnerabilities, lineno: int) -> MultiLabel:
    illegal_multilabel = policy.detect_illegal_flows(func_name, ml)
    if illegal_multilabel:
        lineno = getattr(node, "lineno", None)
        vulnerabilities.add_vulnerability(func_name, illegal_multilabel, lineno)
    return illegal_multilabel