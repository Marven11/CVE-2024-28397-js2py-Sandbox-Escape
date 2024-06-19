
def monkey_patch():
    """Patching js2py for a vulunability
    Test it before using it! I don't guarentee that it won't break your program!
    """
    from js2py.constructors.jsobject import Object
    fn = Object.own["getOwnPropertyNames"]["value"].code
    def wraps(*args, **kwargs):
        result = fn(*args, **kwargs)
        return list(result)
    Object.own["getOwnPropertyNames"]["value"].code = wraps


if __name__ == "__main__":
    monkey_patch()
