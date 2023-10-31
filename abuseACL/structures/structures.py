
from enum import Enum


class ACCESS_MASK(Enum):
    # Perform "Validated writes" (i.e. edit an attribute's value and have that value verified and validate by AD). The "Validated writes" is referenced by an "ObjectType GUID".
    SELF                    = 0x00000008

    # Edit one of the object's attributes. The attribute is referenced by an "ObjectType GUID".
    WRITE_PROPERTIES        = 0x00000020

    # Peform "Extended rights". "AllExtendedRights" refers to that permission being unrestricted. This right can be restricted by specifying the extended right in the "ObjectType GUID".
    ALL_EXTENDED_RIGHTS     = 0x00000100

    # Edit the object's DACL (i.e. "inbound" permissions).
    WRITE_DACL              = 0x00040000

    # Assume the ownership of the object (i.e. new owner of the victim = attacker, cannot be set to another user). 
    # With the "SeRestorePrivilege" right it is possible to specify an arbitrary owner.
    WRITE_OWNER             = 0x00080000

    # Combination of almost all other rights.
    GENERIC_ALL             = 0x10000000

    # Combination of write permissions (Self, WriteProperty) among other things.
    GENERIC_WRITE           = 0x40000000

    FULL_CONTROL            = 0x000f01ff


class RIGHTS_GUID(Enum):
    # Edit the "member" attribute of the object.
    SELF_MEMBERSHIP                 = "bf9679c0-0de6-11d0-a285-00aa003049e2"

    # Change the password of the object without having to know the previous one.
    RESET_PASSWORD                  = "00299570-246d-11d0-a768-00aa006e0529"
    
    # One of the two extended rights needed to operate a DCSync.
    DS_REPLICATION_GET_CHANGES      = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    
    # One of the two extended rights needed to operate a DCSync.
    DS_REPLICATION_GET_CHANGES_ALL  = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    
    # Edit the "servicePrincipalName" attribute of the object.
    VALIDATED_SPN                   = "f3a64788-5306-11d1-a9c5-0000f80367c1"

    # All
    ALL                             = "*"
