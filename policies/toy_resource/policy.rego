package example

# Task 1.
# Check if both conditions are true; Contain at least one RiskyWrite permission, Contain the field encrypted with the false value.


analyze[risk_path] {
    # iteration over indices of the object. 
    some index  
    # Using index to directly access the elements in 'sub_resource_permissions'
    sub_resource := input.sub_resource_permissions[index]  

    # Check for "encrypted": false
    not sub_resource.encrypted
    #check for "RiskyWrite" in acl field.
    #[_]: the way to say "for each element".
    sub_resource.acl[_] == "RiskyWrite"
    
    # if they are both "encrypted" and "RiskyWrite, return the name of the path.
    # sprintf is a func to create a string format. 
    # .%d - will be replaced by the index.
    risk_path := sprintf("sub_resource_permissions.%d.encrypted", [index])
}
