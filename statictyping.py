"""
Module which aims to implement some form of static type checking to 
Python through the use of decorators. This relies on the use of type 
hints, introduced in Python 3.5.

An example usaqge of this program can be seen below with a square root 
function below:

@enforcetypes
def sqrt(num: numbers.Number) -> float:
    return num**0.5

>>> sqrt(2) -- returns 1.4142135623730951
>>> sqrt(3.5) -- returns 1.8708286933869707
>>> sqrt("2") -- raises TypeError

If the signature was changed to provide an incorrect return type, an 
exception will be raised as well.

@enforcetypes
def sqrt(num: numbers.Number) -> str:
    return num**0.5

>>> sqrt(2) -- raises TypeError
"""
import collections.abc
import inspect
import typing


def __make_generic_arg_type_error_message(param_name: str, expected_generic_type: type, generic_param_hint: type, 
                                          strict: bool) -> str:
    """
    Constructs the message to be placed within a TypeError exception 
    that will be raised if the interior type of a generic type-hinted 
    parameter is not correct.

    Args:
        param_name: the name of the parameter from the original function 
            which failed the interior type check.
        expected_generic_type: the expected interior type that the 
            parameter specified by param_name should contain.
        generic_param_hint: the generic type hint of the param_name 
            specified from the original function.
        strict: whether or not strict type checking was enforced.
    
    Returns:
        A message describing the failed interior type check of 
        param_name from the original function, depending on whether 
        strict type checking was used or not.
    """
    if strict:
        return (f"item in '{param_name}' contains an item that does not match the corresponding exact type "
                f"'{expected_generic_type}' for generic type hint '{generic_param_hint}'")
    else:
        return (f"item in '{param_name}' contains an item that does not match an instance of '{expected_generic_type}'"
                f"for generic type hint '{generic_param_hint}'")


def __make_generic_origin_type_error_message(param_name: str, expected_origin_type: type, generic_param_hint: type, 
                                             strict: bool) -> str:
    """
    Constructs the message to be placed within a TypeError exception 
    that will be raised if the base type of a generic type-hinted 
    parameter is not correct.

    Args:
        param_name: the name of the parameter from the original function 
            which failed the base type check.
        expected_origin_type: the expected base type that the parameter 
            specified by param_name should be.
        generic_param_hint: the generic type hint of the param_name 
            specified from the original function.
        strict: whether or not strict type checking was enforced.
    
    Returns:
        A message describing the failed base type check of param_name 
        from the original function, depending on whether strict type 
        checking was used or not.
    """
    if strict:
        return (f"'{param_name}' is not of expected exact type '{expected_origin_type}' for generic type hint "
                f"'{generic_param_hint}'")
    else:
        return (f"'{param_name}' is not an instance of '{expected_origin_type}' for generic type hint "
                f"'{generic_param_hint}'")


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


def __check_generic_collection_type(param: collections.abc.Collection, param_name: str, expected_type: type, 
                            strict: bool) -> bool:
    """
    Checks whether a parameter hinted with a type containing generics is 
    both of the correct base type itself, and contains the correct types 
    as specified by its generic. MyPy standards are utilised to determine 
    what the inner type of the generic object should be.

    Args:
        param: the Collection parameter that will have its base type, 
            and containing types checked according to its generic type 
            hint.
        param_name: the name of the original base parameter being 
            checked.
        expected_type: the expected generic type of param.
        strict: whether or not strict typing was enforced.
    
    Returns:
        True if the parameter contains a correct base and interior types 
        according to its generic type, with False not being returned as 
        an exception is raised instead.
    
    Raises:
        TypeError: if the base or interior types of param do not match 
            the generic type hint specified in expected_type.
    """
    # Check base type
    base_type = typing.get_origin(expected_type)
    if strict:
        if type(param) != base_type:
            raise TypeError(__make_generic_origin_type_error_message(param_name, base_type, expected_type, strict))
    else:
        if not isinstance(param, base_type):
            raise TypeError(__make_generic_origin_type_error_message(param_name, base_type, expected_type, strict))
    
    generic_types = typing.get_args(expected_type)

    # Split depending if object is a Mapping object
    if isinstance(param, collections.abc.Mapping):
        if len(generic_types) != 2:
            raise TypeError(f"a 'Mapping' instance must have generic arguments of length 2, got '{expected_type}'")
        
        expected_k_type, expected_v_type = generic_types
        for key, value in param.items():
            try:
                __check_if_type_is_valid(key, param_name, expected_k_type, strict)
            except TypeError:
                raise TypeError(__make_generic_arg_type_error_message(param_name, expected_k_type, expected_type, strict))
            
            try:
                __check_if_type_is_valid(value, param_name, expected_k_type, strict)
            except TypeError:
                raise TypeError(__make_generic_arg_type_error_message(param_name, expected_v_type, expected_type, strict))
    # Is a Callable -- recurse:
    elif isinstance(param, (typing.Callable, collections.abc.Callable)):
        enforcetypes(param, strict)
    # Is a tuple -- expected order:
    elif isinstance(param, tuple):
        # If ellipsis, everything must be of the same type
        if Ellipsis in generic_types:
            if len(generic_types) != 2:
                raise TypeError("Ellipsis in tuple generic should only contain a single generic argument with the Ellipsis")
            
            generic_types = (generic_types[0])*len(param)

        for param_value, expected_tuple_type in zip(param, generic_types):            
            try:
                __check_if_type_is_valid(param_value, param_name, expected_tuple_type, strict)
            except TypeError:
                raise TypeError(__make_generic_arg_type_error_message(param_name, expected_tuple_type, expected_type, strict))
    # Some other collection/container
    else:
        if len(generic_types) != 1:
            raise TypeError(f"a 'Collection' instance must have a single generic argument, got '{expected_type}' -- "
                            "maybe you meant to include the types as a Union instead?")
        
        expected_interior_type = generic_types[0]
        for param_value in param:
            try:
                __check_if_type_is_valid(param_value, param_name, expected_interior_type, strict)
            except TypeError:
                raise TypeError(__make_generic_arg_type_error_message(param_name, expected_interior_type, expected_type, strict))
    
    return True


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
    if expected_type in {inspect.Parameter.empty, typing.Any}:
        return

    origin_type = typing.get_origin(expected_type)

    if strict:
        if origin_type is not None:
            if origin_type is typing.Union:
                type_is_valid = type(param) in typing.get_args(expected_type)
            else:
                type_is_valid = __check_generic_collection_type(param, param_name, expected_type, strict)
        elif expected_type is None:
            type_is_valid = param is None
        else:
            type_is_valid = type(param) == expected_type
    else:
        if origin_type is not None:
            if origin_type is typing.Union:
                type_is_valid = isinstance(param, typing.get_args(expected_type))
            else:    
                type_is_valid = __check_generic_collection_type(param, param_name, expected_type, strict)
        elif expected_type is None:
            type_is_valid = param is None
        else:
            type_is_valid = isinstance(param, expected_type)
    
    if not type_is_valid:
        raise TypeError(__make_type_error_message(param_name, expected_type, strict))


def enforcetypes(func: typing.Callable[..., typing.Any], strict: bool = False) -> typing.Callable[..., typing.Any]:
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
    if not isinstance(func, (typing.Callable, collections.abc.Callable)):
        raise TypeError("'func' must be an instance of a 'Callable' type in order to be type checked")
    elif not isinstance(strict, bool):
        raise TypeError("'strict' parameter must be a 'bool' instance")

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
