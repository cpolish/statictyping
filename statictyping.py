"""
Module which aims to implement some form of static type checking to 
Python through the use of decorators. This relies on the use of type 
hints, introduced in Python 3.5.

An example usaqge of this program can be seen below with a square root 
function below:

@enforcetypes
def sqrt(num: numbers.Number) -> float:
    return num**0.5

>> sqrt(2) -- returns 1.4142135623730951
>> sqrt(3.5) -- returns 1.8708286933869707
>> sqrt("2") -- raises TypeError

If the signature was changed to provide an incorrect return type, an 
exception will be raised as well.

@enforcetypes
def sqrt(num: numbers.Number) -> str:
    return num**0.5

>> sqrt(2) -- raises TypeError
"""
import inspect
import typing


def __make_type_error_message(param_name: str, expected_type: type, strict: bool) -> str:
    """
    Constructs the message to be placed within a TypeError exception 
    that will be raised if a parameter is found to be of an incorrect 
    type.

    Args:
        param_name: the name of the parameter from the original function 
            which failed the type check.
        expected_type: the expected type that the parameter specified by 
            param_name should be.
        strict: whether or not strict type checking was enforced.
    
    Returns:
        A message describing the failed type check of param_name from 
        the original function, depending on whether strict type checking 
        was used or not.
    """
    if strict:
        return f"'{param_name}' is not of expected exact type '{str(expected_type)}'"
    else:
        return f"'{param_name}' is not an instance of '{str(expected_type)}'"


def __check_if_type_is_valid(param: typing.Any, param_name: str, expected_type: type, strict: bool) -> None:
    """
    Checks whether a parameter either matches a given type, or is an 
    instance of a given type, depending on whether strict type checking 
    is enforced or not.

    Args:
        param: the parameter of a function that is to be type checked.
        param_name: the name of the above specified parameter from the 
            original function.
        expected_type: the type that param must either match exactly, if 
            strict = True, or is an instance of, if strict = False
        strict: whether strict type checking is to be used or not. If 
            this is True, the type of param will be checked by equality 
            to the type specified in expected_type, otherwise, it will 
            be checked whether param is an instance of expected_type.
    
    Raises:
        TypeError: if param either does not match, or is not an instance 
            of, expected_type.
    """
    if expected_type is inspect.Parameter.empty:
        return

    if strict:
        type_is_valid = type(param) == expected_type
    else:
        type_is_valid = isinstance(param, expected_type)
    
    if not type_is_valid:
        raise TypeError(__make_type_error_message(param_name, expected_type, strict))


def enforcetypes(func: typing.Callable, strict: bool = False) -> typing.Callable:
    """
    Decorator which can be used to enforce the parameter and return 
    types of a function according to type hints provided in the 
    function's signature. When such a decorated function is called, if 
    the function's arguments, or the function's return type does not 
    match those specified in the function's signature, an exception is 
    raised.

    Args:
        func: the function that the decorator is working with.
        strict: optional parameter which specifies whether strict type 
            checking should be implemented -- by default, False. If 
            this is set to True, the types specified in the function 
            type hints will check for type equality of the parameters/
            function return type, rather than using the 'isinstance' 
            method.
    
    Returns:
        the original function that was decorated, after type 
        checking has been performed.
    
    Raises:
        TypeError: if the type of an argument or the function's 
            return type does not match the function's signature.
    """
    __check_if_type_is_valid(func, "func", typing.Callable, False)
    __check_if_type_is_valid(strict, "strict", bool, False)

    func_signature = inspect.signature(func)
    func_params = func_signature.parameters
    func_return_type = func_signature.return_annotation

    def wrapper_func(*args, **kwargs) -> typing.Any:
        params_to_check = func_params.copy()

        for kwarg_key, kwarg_value in kwargs.items():
            if func_params.get(kwarg_key) is not None:
                expected_kwarg_type = func_params[kwarg_key].annotation
                __check_if_type_is_valid(kwarg_value, kwarg_key, expected_kwarg_type, strict)
                del params_to_check[kwarg_key]
        
        for func_arg, (expected_arg_name, expected_arg_type) in zip(args, params_to_check.items()):
            __check_if_type_is_valid(func_arg, expected_arg_name, expected_arg_type.annotation, strict)
        
        func_result = func(*args, **kwargs)
        __check_if_type_is_valid(func_result, "return type", func_return_type, strict)
        return func_result

    return wrapper_func
