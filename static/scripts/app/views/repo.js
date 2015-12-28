define([
    'jquery',
    'underscore',
    'backbone',
    'common',
    'app/views/share',
    'app/views/dialogs/history-settings',
    'app/views/dialogs/repo-permissions',
    'app/views/dialogs/repo-share-link-admin'
], function($, _, Backbone, Common, ShareView, HistorySettingsDialog,
    RepoPermissionsDialog, RepoShareLinkAdminDialog) {
    'use strict';

    var RepoView = Backbone.View.extend({
        tagName: 'tr',

        template: _.template($('#repo-tmpl').html()),
        repoDelConfirmTemplate: _.template($('#repo-del-confirm-template').html()),
        renameTemplate: _.template($("#repo-rename-form-template").html()),

        events: {
            'mouseenter': 'highlight',
            'mouseleave': 'rmHighlight',
            'click .repo-delete-btn': 'del',
            'click .repo-share-btn': 'share',
            'click .js-toggle-popup': 'togglePopup',
            'click .js-repo-rename': 'rename',
            'click .js-popup-history-settings': 'popupHistorySettings',
            'click .js-popup-permission-settings': 'popupPermissionSettings',
            'click .js-popup-share-link-admin': 'popupShareLinkAdmin'
        },

        initialize: function() {
        },

        render: function() {
            var obj = this.model.toJSON();
            $.extend(obj, {
                enable_repo_history_setting: app.pageOptions.enable_repo_history_setting
            });
            this.$el.html(this.template(obj));
            return this;
        },

        // disable 'hover' when 'repo-del-confirm' popup is shown
        highlight: function() {
            if ($('#my-own-repos .repo-del-confirm').length == 0
                && !$('.hidden-op:visible').length
                && !$('#repo-rename-form').length) {
                this.$el.addClass('hl').find('.op-icon').removeClass('vh');
            }
        },

        rmHighlight: function() {
            if ($('#my-own-repos .repo-del-confirm').length == 0
                && !$('.hidden-op:visible').length
                && !$('#repo-rename-form').length) {
                this.$el.removeClass('hl').find('.op-icon').addClass('vh');
            }
        },

        del: function() {
            var del_icon = this.$('.repo-delete-btn');
            var op_container = this.$('.op-container').css({'position': 'relative'});

            var confirm_msg = gettext("Really want to delete {lib_name}?")
                .replace('{lib_name}', '<span class="op-target">' + Common.HTMLescape(this.model.get('name')) + '</span>');
            var confirm_popup = $(this.repoDelConfirmTemplate({
                content: confirm_msg
            }))
            .appendTo(op_container)
            .css({
                'left': del_icon.position().left,
                'top': del_icon.position().top + del_icon.height() + 2,
                'width': 180
            });

            var _this = this;
            $('.no', confirm_popup).click(function() {
                confirm_popup.addClass('hide').remove(); // `addClass('hide')`: to rm cursor
                _this.rmHighlight();
            });
            $('.yes', confirm_popup).click(function() {
                $.ajax({
                    url: Common.getUrl({'name':'repo_del', 'repo_id': _this.model.get('id')}),
                    type: 'POST',
                    dataType: 'json',
                    beforeSend: Common.prepareCSRFToken,
                    success: function(data) {
                        _this.remove();
                        Common.feedback(gettext("Delete succeeded."), 'success');
                    },
                    error: function(xhr) {
                        confirm_popup.addClass('hide').remove();
                        _this.rmHighlight();

                        var err;
                        if (xhr.responseText) {
                            err = $.parseJSON(xhr.responseText).error;
                        } else {
                            err = gettext("Failed. Please check the network.");
                        }
                        Common.feedback(err, 'error');
                    }
                });
            });
        },

        share: function() {
            var options = {
                'is_repo_owner': true,
                'is_virtual': this.model.get('virtual'),
                'user_perm': 'rw',
                'repo_id': this.model.get('id'),
                'repo_encrypted': this.model.get('encrypted'),
                'is_dir': true,
                'dirent_path': '/',
                'obj_name': this.model.get('name')
            };
            new ShareView(options);
        },

        togglePopup: function() {
            var icon = this.$('.js-toggle-popup'),
            popup = this.$('.hidden-op');

            if (popup.hasClass('hide')) { // the popup is not shown
                popup.css({'left': icon.position().left});
                if (icon.offset().top + popup.height() <= $('#main').offset().top + $('#main').height()) {
                    // below the icon
                    popup.css('top', icon.position().top + icon.height() + 3);
                } else {
                    popup.css('bottom', icon.parent().outerHeight() - icon.position().top + 3);
                }
                popup.removeClass('hide');
            } else {
                popup.addClass('hide');
            }
        },

        rename: function() {
            var repo_name = this.model.get('name');

            var form = $(this.renameTemplate({
                repo_name: repo_name
            }));


            var $name_span = this.$('.repo-name-span'),
                $op_td = this.$('.repo-op-td'),
                $name_td = $name_span.closest('td');
            $name_td.attr('colspan', 2).css({
                'width': $name_span.width() + $op_td.outerWidth(),
                'height': $name_span.height()
            }).append(form);
            $op_td.hide();
            $name_span.hide();

            this.togglePopup();

            var cancelRename = function() {
                form.remove();
                $op_td.show();
                $name_span.show();
                $name_td.attr('colspan', 1).css({
                    'width': $name_span.width()
                });
                return false; // stop bubbling (to 'doc click to hide .hidden-op')
            };
            $('.cancel', form).click(cancelRename);

            return false;
        },

        popupHistorySettings: function() {
            var options = {
                'repo_name': this.model.get('name'),
                'repo_id': this.model.get('id')
            };
            this.togglePopup(); // close the popup
            new HistorySettingsDialog(options);
            return false;
        },

        popupPermissionSettings: function() {
            var options = {
                'repo_name': this.model.get('name'),
                'repo_id': this.model.get('id')
            };
            this.togglePopup(); // close the popup
            new RepoPermissionsDialog(options);
            return false;
        },

        popupShareLinkAdmin: function() {
            var options = {
                'repo_name': this.model.get('name'),
                'repo_id': this.model.get('id')
            };
            this.togglePopup(); // close the popup
            new RepoShareLinkAdminDialog(options);
            return false;
        }

    });

    return RepoView;
});
