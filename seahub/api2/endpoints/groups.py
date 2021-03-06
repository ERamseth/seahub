import logging

from django.utils.dateformat import DateFormat
from django.utils.translation import ugettext as _
from django.template.defaultfilters import filesizeformat

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import seaserv
from seaserv import seafile_api
from pysearpc import SearpcError

from seahub.api2.utils import api_error
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.avatar.settings import GROUP_AVATAR_DEFAULT_SIZE
from seahub.avatar.templatetags.group_avatar_tags import api_grp_avatar_url, \
    get_default_group_avatar_url
from seahub.utils import is_org_context, is_valid_username
from seahub.utils.timeutils import dt, utc_to_local
from seahub.group.utils import validate_group_name, check_group_name_conflict
from seahub.group.views import remove_group_common
from seahub.base.templatetags.seahub_tags import email2nickname, \
    translate_seahub_time

from .utils import api_check_group_staff

logger = logging.getLogger(__name__)

def get_group_admins(group_id):
    members = seaserv.get_group_members(group_id)
    admin_members = filter(lambda m: m.is_staff, members)

    admins = []
    for u in admin_members:
        admins.append(u.user_name)

    return admins

def get_group_info(request, group_id, avatar_size=GROUP_AVATAR_DEFAULT_SIZE):
    group = seaserv.get_group(group_id)
    try:
        avatar_url, is_default, date_uploaded = api_grp_avatar_url(group.id, avatar_size)
    except Exception as e:
        logger.error(e)
        avatar_url = get_default_group_avatar_url()

    val = utc_to_local(dt(group.timestamp))
    group_info = {
        "id": group.id,
        "name": group.group_name,
        "creator": group.creator_name,
        "created_at": val.strftime("%Y-%m-%dT%H:%M:%S") + DateFormat(val).format('O'),
        "avatar_url": request.build_absolute_uri(avatar_url),
        "admins": get_group_admins(group.id),
    }

    return group_info


class Groups(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    def _can_add_group(self, request):
        return request.user.permissions.can_add_group()

    def get(self, request):
        """ List all groups.
        """

        org_id = None
        username = request.user.username
        if is_org_context(request):
            org_id = request.user.org.org_id
            user_groups = seaserv.get_org_groups_by_user(org_id, username)
        else:
            user_groups = seaserv.get_personal_groups_by_user(username)

        try:
            size = int(request.GET.get('avatar_size', GROUP_AVATAR_DEFAULT_SIZE))
        except ValueError:
            size = GROUP_AVATAR_DEFAULT_SIZE

        try:
            with_repos = int(request.GET.get('with_repos', 0))
        except ValueError:
            with_repos = 0

        if with_repos not in (0, 1):
            error_msg = _(u'Argument can only be 0 or 1')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        groups = []
        for g in user_groups:
            group_info = get_group_info(request, g.id , size)

            if with_repos:
                if org_id:
                    group_repos = seafile_api.get_org_group_repos(org_id, g.id)
                else:
                    group_repos = seafile_api.get_repos_by_group(g.id)

                repos = []
                for r in group_repos:
                    repo = {
                        "id": r.id,
                        "name": r.name,
                        "desc": r.desc,
                        "size": r.size,
                        "size_formatted": filesizeformat(r.size),
                        "mtime": r.last_modified,
                        "mtime_relative": translate_seahub_time(r.last_modified),
                        "encrypted": r.encrypted,
                        "permission": r.permission,
                        "owner": r.user,
                        "owner_nickname": email2nickname(r.user),
                        "share_from_me": True if username == r.user else False,
                    }
                    repos.append(repo)

                group_info['repos'] = repos

            groups.append(group_info)

        return Response(groups)

    def post(self, request):
        """ Create a group
        """
        if not self._can_add_group(request):
            error_msg = _(u'You do not have permission to create group.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        group_name = request.data.get('name', '')
        group_name = group_name.strip()

        # Check whether group name is validate.
        if not validate_group_name(group_name):
            error_msg = _(u'Group name can only contain letters, numbers, blank, hyphen or underscore')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # Check whether group name is duplicated.
        if check_group_name_conflict(request, group_name):
            error_msg = _(u'There is already a group with that name.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # create group.
        try:
            group_id = seaserv.ccnet_threaded_rpc.create_group(group_name, username)
        except SearpcError as e:
            logger.error(e)
            error_msg = _(u'Failed')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # get info of new group
        group_info = get_group_info(request, group_id, GROUP_AVATAR_DEFAULT_SIZE)

        return Response(group_info, status=status.HTTP_201_CREATED)


class Group(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @api_check_group_staff
    def put(self, request, group_id):
        """ Rename, transfer a specific group
        """

        group = seaserv.get_group(group_id)
        username = request.user.username

        new_group_name = request.data.get('name', None)
        if new_group_name:
            # rename a group
            # Check whether group name is validate.
            if not validate_group_name(new_group_name):
                error_msg = _(u'Group name can only contain letters, numbers, blank, hyphen or underscore')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # Check whether group name is duplicated.
            if check_group_name_conflict(request, new_group_name):
                error_msg = _(u'There is already a group with that name.')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                seaserv.ccnet_threaded_rpc.set_group_name(group_id, new_group_name)
            except SearpcError as e:
                logger.error(e)
                error_msg = _(u'Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        new_creator= request.data.get('creator', None)
        if new_creator:
            # transfer a group
            if not is_valid_username(new_creator):
                error_msg = _('Creator %s is not valid.') % new_creator
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if new_creator == group.creator_name:
                error_msg = _('%s is already group owner') % new_creator
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                if not seaserv.is_group_user(group_id, new_creator):
                    seaserv.ccnet_threaded_rpc.group_add_member(group_id, username, new_creator)

                if not seaserv.check_group_staff(group_id, new_creator):
                    seaserv.ccnet_threaded_rpc.group_set_admin(group_id, new_creator)

                seaserv.ccnet_threaded_rpc.set_group_creator(group_id, new_creator)
            except SearpcError as e:
                logger.error(e)
                error_msg = _(u'Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # get new info of this group
        group_info = get_group_info(request, group_id, GROUP_AVATAR_DEFAULT_SIZE)

        return Response(group_info)

    @api_check_group_staff
    def delete(self, request, group_id):
        """ Delete a specific group
        """

        username = request.user.username

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        try:
            remove_group_common(group_id, username, org_id=org_id)
        except SearpcError as e:
            logger.error(e)
            error_msg = _(u'Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({'success': True})
