from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsStaffOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        is_staff = bool(request.user and request.user.is_staff) # user exists and has staff status
        return is_staff or request.method in SAFE_METHODS # safe method = GET, HEAD, OPTIONS


class IsAdminForDeleteOrPatchAndReadOnly(BasePermission):
    # only admin can delete, staff can patch/post/put, everyone else can read only
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True 
        elif request.method == 'DELETE':
            return bool(request.user and request.user.is_superuser)
        else:
            return bool(request.user and request.user.is_staff)


class IsOwnerOrAdmin(BasePermission):
    # everyone can read only, admins can delete and owner of the object can edit (PUT, PATCH)
    # -> you can edit your own profile but not anyone else's
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True 
        elif request.method == 'DELETE':
            return bool(request.user and request.user.is_superuser)
        else:
            return bool(request.user and request.user == obj.user)