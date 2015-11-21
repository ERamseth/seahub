define([
    'jquery',
    'underscore',
    'backbone',
    'common',
    'app/views/myhome-repos',
    'app/views/myhome-sub-repos',
    'app/views/myhome-shared-repos',
    'app/views/starred-file',
    'app/views/activities'
], function($, _, Backbone, Common, ReposView, SubReposView,
    SharedReposView, StarredFileView, ActivitiesView) {
    'use strict';

    var MyHomeView = Backbone.View.extend({
        el: '#main',

        initialize: function(options) {
            this.reposView = new ReposView();
            this.subReposView = new SubReposView();
            this.sharedReposView = new SharedReposView();
            this.starredFileView = new StarredFileView();
            this.activitiesView = new ActivitiesView();

            this.dirView = options.dirView;

            this.currentView = this.reposView;

            $('#initial-loading-view').hide();
        },

        showMyRepos: function() {
            this.currentView.hide();
            this.reposView.show();
            this.currentView = this.reposView;
        },

        showMySubRepos: function() {
            this.currentView.hide();
            this.subReposView.show();
            this.currentView = this.subReposView;
        },

        showSharedRepos: function() {
            this.currentView.hide();
            this.sharedReposView.show();
            this.currentView = this.sharedReposView;
        },

        showStarredFile: function() {
            this.currentView.hide();
            this.starredFileView.show();
            this.currentView = this.starredFileView;
        },

        showActivities: function() {
            this.currentView.hide();
            this.activitiesView.show();
            this.currentView = this.activitiesView;
        },

        showDir: function(category, repo_id, path) {
            var path = path || '/';
            this.currentView.hide();
            this.dirView.showDir(category, repo_id, path);
            this.currentView = this.dirView;
        },

        hide: function() {
            this.currentView.hide();
        }

    });

    return MyHomeView;
});
