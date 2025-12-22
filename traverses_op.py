import ast
from Policy import Policy
from MultiLabel import MultiLabel
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities
import traverses_op

#######################
# Expression Handlers #
######################

# Simple dispatcher for expression evaluation

def traverse_Name(node: ast.Name, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Name nodes.
    """
    # Return the multilabel associated with this variable name
    return multiLabelling.get_multilabel(node.id)
    
def traverse_Call(node: ast.Call, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Call nodes.
    """
    
    # Implement logic for handling ast.Call nodes
    
#     print(ast.dump(ast.parse('func(a, b=c, *d, **e)', mode='eval'), indent=4))
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
    
    combined_ml = MultiLabel(policy.patterns)
    # Evaluate function name
    func_ml = eval_expr(node.func, policy, multiLabelling, vulnerabilities)
    combined_ml = combined_ml.combinor(func_ml)
    # Evaluate positional arguments
    for arg in node.args:
        arg_ml = eval_expr(arg, policy, multiLabelling, vulnerabilities)
        combined_ml = combined_ml.combinor(arg_ml)
    # Evaluate keyword arguments
    for keyword in node.keywords: # TODO NAO TENHO A CERTEZA SE ISTO COBRE A PARTE DO keyword(...
        kwarg_ml = eval_expr(keyword.value, policy, multiLabelling, vulnerabilities)
        combined_ml = combined_ml.combinor(kwarg_ml)
    
    
def traverse_UnaryOp(node: ast.UnaryOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.UnaryOp nodes.
    """
    
    # UnaryOp(unaryop op, expr operand)
    
    # Evaluate operand and return its multilabel (unary ops don't change labels)
    return eval_expr(node.operand, policy, multiLabelling, vulnerabilities)
    
    

def traverse_BoolOp(node: ast.BoolOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.BoolOp nodes.
    """
    # BoolOp(boolop op, expr* values)
    # Implement logic for handling ast.BoolOp nodes
    
    # x and y and z --> values = [x, [y, z]] e depois ele avaliava o x dentro 
    # do eval_expr como um name e retornava o multilabel associado ao x
    # o y,z seriam avaliados recursivamente primeiro como um novo BoolOp
    # e depois o resultado combinado seria combinado com o multilabel do x
    
    #print(ast.dump(ast.parse('x or y', mode='eval'), indent=4))
        # Expression(
        #     body=BoolOp(
        #         op=Or(),
        #         values=[
        #             Name(id='x', ctx=Load()),
        #             Name(id='y', ctx=Load())]))
    
    combined_ml = MultiLabel(policy.patterns)
    for value in node.values:
        value_ml = eval_expr(value, policy, multiLabelling, vulnerabilities)
        combined_ml = combined_ml.combinor(value_ml)
        
    return combined_ml


def traverse_Constant(node: ast.Constant, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities): 
    """
    Handles traversal of ast.Constant nodes.
    """
    
    # print(ast.dump(ast.parse('123', mode='eval'), indent=4))
    #     Expression(
    #         body=Constant(value=123))
    
    # Constants carry no sources; return an empty multilabel across patterns
    # Simplesmente criamos uma nova label
    return MultiLabel(policy.patterns)

def traverse_BinOp(node: ast.BinOp, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.BinOp nodes.
    """
    
    # print(ast.dump(ast.parse('x + y', mode='eval'), indent=4))
    #     Expression(
    #         body=BinOp(
    #             left=Name(id='x', ctx=Load()),
    #             op=Add(),
    #             right=Name(id='y', ctx=Load())))
    
    # Combine multilabels from left and right expressions
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities)
    right_ml = eval_expr(node.right, policy, multiLabelling, vulnerabilities)
    return left_ml.combinor(right_ml)

def traverse_Compare(node: ast.Compare, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):    
    """
    Handles traversal of ast.Compare nodes.
    """
    # Implement logic for handling ast.Compare nodes
    
    # print(ast.dump(ast.parse('1 <= a < 10', mode='eval'), indent=4))
    #     Expression(
    #         body=Compare(
    #             left=Constant(value=1),
    #             ops=[
    #                 LtE(),
    #                 Lt()],
    #             comparators=[
    #                 Name(id='a', ctx=Load()),
    #                 Constant(value=10)]))
    
    # Compare(expr left, cmpop* ops, expr* comparators)
    
    left_ml = eval_expr(node.left, policy, multiLabelling, vulnerabilities)
    
    for comparator in node.comparators:
        comp_ml = eval_expr(comparator, policy, multiLabelling, vulnerabilities)
        left_ml = left_ml.combinor(comp_ml)

    return left_ml

def traverse_Attribute(node: ast.Attribute, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Attribute nodes.
    """
    # Implement logic for handling ast.Attribute nodes
    
    # Attribute(expr value, identifier attr, expr_context ctx)
    
    # print(ast.dump(ast.parse('snake.colour', mode='eval'), indent=4))
    #     Expression(
    #         body=Attribute(
    #             value=Name(id='snake', ctx=Load()),
    #             attr='colour',
    #             ctx=Load()))
    
    return eval_expr(node.value, policy, multiLabelling, vulnerabilities)
    
def traverse_Subscript(node: ast.Subscript, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Subscript nodes.
    """
    # Implement logic for handling ast.Subscript nodes
    
    # print(ast.dump(ast.parse('l[1:2, 3]', mode='eval'), indent=4))
        # Expression(
        #     body=Subscript(
        #         value=Name(id='l', ctx=Load()),
        #         slice=Tuple(
        #             elts=[
        #                 Slice(
        #                     lower=Constant(value=1),
        #                     upper=Constant(value=2)),
        #                 Constant(value=3)],
        #             ctx=Load()),
        #         ctx=Load()))
    # Subscript(expr value, expr slice, expr_context ctx)
    
    # TODO handle slice properly ??????? PRECISAMOS DE OS AVALIAR? NOT SURE PROVAVELEMTNE SIM
    # VOU METER UMA VERSAO COM AVALIAÇAO DAS SLICES MAS DESPOIS CONFIRMAR
    
    value_ml = eval_expr(node.value, policy, multiLabelling, vulnerabilities)
    slice_ml = eval_expr(node.slice, policy, multiLabelling, vulnerabilities)
    return value_ml.combinor(slice_ml)
    
    
    
#######################
# Statement Handlers  #
######################

def traverse_Assign(node: ast.Assign, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Assign nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.Assign nodes

def traverse_If(node: ast.If, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):    
    """
    Handles traversal of ast.If nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.If nodes

def traverse_While(node: ast.While, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.While nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.While nodes

def traverse_Expr(node: ast.Expr, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Expr nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.Expr nodes
    
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

def eval_expr(node: ast.AST, policy: Policy, multiLabelling: MultiLabelling, vulnerabilities: Vulnerabilities) -> MultiLabel:
    handler = EXPR_DISPATCH.get(type(node))
    if handler:
        return handler(node, policy, multiLabelling, vulnerabilities)
    # Fallback: return an empty multilabel across policy patterns
    return MultiLabel(policy.patterns)
    