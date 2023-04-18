/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 (function() {
    'use strict';

    function DeletePolicyController($rootScope, $uibModalInstance, policy, toaster, PoliciesService) {
        var self = this;
    
        self.policy = policy;
        self.enabled = true;
        self.error = undefined;
        
        self.deletePolicy = function (policy) {
            self.error = undefined;
            self.enabled = false;
            PoliciesService.removePolicy(policy).then(
                function(response) {
                    console.info("Policy deleted", policy.id);
                    $uibModalInstance.close(policy);
                    $rootScope.policiesCount--;
                    self.enabled = true;
                },
                function (error) {
                console.error('Error deleting policy', error);
                self.error = error;
                self.enabled = true;
                toaster.pop({ type: 'error', body: error.data.error_description});
                });
        }
        self.cancel = function () {
          $uibModalInstance.dismiss('Dismissed');
        };
      }

    function AddPolicyController(GroupsService, $rootScope, $scope, $uibModal, $uibModalInstance, toaster, PoliciesService, scimFactory, ScopesService) {
        var self = this;
        self.groups = [];
        self.accounts = [];
        self.scopes = [];
        var USERS_CHUNCK_SIZE = 100;
        self.selectedScopes = [];
        self.selectedGroups = [];
        self.selectedUsers = [];

        self.$onInit = function () {
          self.enabled = true;
          self.reset();

        GroupsService.getAllGroups().then(
          function (res) {
              self.groups = res;
            });

        scimFactory.getAllUsers(USERS_CHUNCK_SIZE)
            .then(function(data) {
                self.accounts = data;
        });

        ScopesService.getAllScopes().then(
          function(res) {
            self.scopes = res.data;
          });
      }

        self.reset = function () {
          self.policy = {
            description: null,
            rule: '',
            matchingPolicy: ''
          };
          self.selectedUsers = [];
          self.selectedGroups = [];
          self.selectedScopes = [];

          if ($scope.policyCreationForm) {
            $scope.policyCreationForm.$setPristine();
          }
          self.enabled = true;
        }

        self.submit = function () {

          console.log("Policy info to add ", self.policy);
          self.enabled = false;

          var newPolicy = {};

          newPolicy.id = self.policy.id;
          newPolicy.description = self.policy.description;
          newPolicy.rule = self.policy.rule;
          newPolicy.matchingPolicy = self.policy.matchingPolicy;

          self.selectedUsers.filter(function(user) {
            newPolicy.account = {
              uuid: user.id
            };
          });

          self.selectedGroups.filter(function(group) {
            newPolicy.group = {
              uuid: group.id
            };
          });

          newPolicy.scopes = [];
          self.selectedScopes.forEach(function(scope) {
            newPolicy.scopes.push(scope.value);
          });

          console.info("Adding policy ... ", newPolicy);

          PoliciesService.addPolicy(newPolicy).then(
            function(response) {
                console.info("Policy Created", response.data);
                $uibModalInstance.close(response.data);
                self.enabled = true;
              },
            function (error) {
              console.error('Error creating policy', error);
              self.error = error;
              self.enabled = true;
              toaster.pop({ type: 'error', body: error.data.error});
            });
        }

        self.cancel = function () {
          $uibModalInstance.dismiss("cancel");
        }

        self.getAllGroups = function() {
        GroupsService.getAllGroups().then(
          function (res) {
              self.groups = res;
          });
        }

        self.loadUsers = function() {
          scimFactory.getAllUsers(USERS_CHUNCK_SIZE)
            .then(function(data) {
                self.accounts = data;
            },
            function(error) {
                console.log('error while loading users', error);
                toaster.pop({ type: 'error', body: error });
            });
        }

        self.loadScopes = function() {
          ScopesService.getAllScopes().then(
            function(res) {
              self.scopes = res.data;
            });
        }
    }

    function EditPolicyController($rootScope, $scope, $uibModal, $uibModalInstance, policy, toaster, PoliciesService) {

      var self = this;

      self.policy = policy;

      self.$onInit = function () {
        self.enabled = true;
      }

      self.updatePolicy = function (policy) {

        self.policy = policy;

        console.log("Policy info to add ", self.policy);
        self.enabled = false;

        var editedPolicy = {};

        editedPolicy.id = self.policy.id;
        editedPolicy.description = self.policy.description;
        editedPolicy.rule = self.policy.rule;
        editedPolicy.matchingPolicy = self.policy.matchingPolicy;
        editedPolicy.account = self.policy.account;
        editedPolicy.group = self.policy.group;
        editedPolicy.scopes = self.policy.scopes;

        console.info("Updating policy ... ", editedPolicy.id, editedPolicy);

        PoliciesService.updatePolicyById(editedPolicy).then(
          function(response) {
              console.info("Policy Updated", editedPolicy.id);
              //$rootScope.policiesCount++;
              $uibModalInstance.close(response.data);
              self.enabled = true;
            },
          function (error) {
            console.error('Error updating policy', error);
            self.error = error;
            self.enabled = true;
            toaster.pop({ type: 'error', body: error.data.error_description});
          });
      }

      self.cancel = function () {
        $uibModalInstance.dismiss("cancel");
      }
    }

	function GroupSelectorController($rootScope, $scope, $uibModal, $uibModalInstance, policy, toaster, PoliciesService) {
        var self = this;
	}
	
	function UserSelectorController($rootScope, $scope, $uibModal, $uibModalInstance, policy, toaster, PoliciesService) {
        var self = this;
	}

    function PoliciesListController($q, $scope, $rootScope, $uibModal, ModalService,
        PoliciesService, toaster) {

      var self = this;
      
      self.$onInit = function() {
          self.policies = [];
          self.loadData(1);
      };
      
      self.openLoadingModal = function() {
          $rootScope.pageLoadingProgress = 0;
          self.modal = $uibModal.open({
              animation: false,
              templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
          });
          return self.modal.opened;
      };

      self.closeLoadingModal = function() {
          $rootScope.pageLoadingProgress = 100;
          self.modal.dismiss('Cancel');
      };

      self.handleError = function(error) {
          console.error(error);
          toaster.pop({ type: 'error', body: error });
      };


      self.loadAllPolicies = function(page) {

        //Pagination Control
			  self.totalResults = self.policies.length;
        self.currentOffset = 1;
        self.curPage = page;
        self.itemsPerPage = 10;
        self.maxSize = 5;

        return PoliciesService.getAllPolicies().then(function(r) {
            self.policies = r.data;
            $rootScope.policiesCount = self.policies.length;
            console.debug("init PoliciesListController", self.policies);

			  self.filteredItems = [];

			  self.numOfPages = function () {
			  return Math.ceil(self.policies.length / self.itemsPerPage);
 
			  };
 
			  $scope.$watch('self.curPage + self.numOfPage', function() {
			  var begin = ((self.curPage - 1) * self.itemsPerPage),
			  end = begin + self.itemsPerPage;

			  self.filteredItems = self.policies.slice(begin, end);
			  });
			  
			  return self.filteredItems;

        }).catch(function(r) {
            $q.reject(r);
        })
      };

      self.loadData = function(page) {
          return self.openLoadingModal()
              .then(function() {
                  var promises = [];
                  promises.push(self.loadAllPolicies(page));
                  return $q.all(promises);
              })
              .then(function(response) {
                  self.closeLoadingModal();
                  self.loaded = true;
              })
              .catch(self.handleError);
      };

      self.handleDeleteSuccess = function (policy) {
        self.enabled = true;
        toaster.pop({
          type: 'success',
          body: 'Policy ' + policy.id + ' has been deleted successfully'
        });
        self.totalResults--;
        if (self.currentOffset > self.totalResults) {
            if (self.curPage > 1) {
              self.curPage--;
            }
          }
        self.loadData(self.curPage);
      };
  
      self.openDeletePolicyDialog = function (policy) {
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/policies/policieslist/policy.delete.dialog.html',
          controller: DeletePolicyController,
          controllerAs: '$ctrl',
          resolve: {
            policy: policy
          }
        });
  
        modalInstance.result.then(self.handleDeleteSuccess);
      };

      self.handleAddPolicySuccess = function () {
        toaster.pop({
          type: 'success',
          body: 'Policy successfully added'
        });
		    self.loadData(self.curPage);
      };
  
      self.openAddPolicyDialog = function () {
  
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/policies/policieslist/policy.add.dialog.html',
          controller: AddPolicyController,
          controllerAs: '$ctrl'
        });
        console.debug(modalInstance);
        modalInstance.result.then(self.handleAddPolicySuccess);
      };

	  self.openGroupSelectorDialog = function () {
  
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/policies/policieslist/group.selector.dialog.html',
          controller: GroupSelectorController,
          controllerAs: '$ctrl'
        });
        console.debug(modalInstance);
        modalInstance.result.then(self.handleAddPolicySuccess);
      };

	  self.openUserSelectorDialog = function () {
  
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/policies/policieslist/user.selector.dialog.html',
          controller: UserSelectorController,
          controllerAs: '$ctrl'
        });
        console.debug(modalInstance);
        modalInstance.result.then(self.handleAddPolicySuccess);
      };

      self.handleEditPolicySuccess = function (policy) {
        toaster.pop({
          type: 'success',
          body: 'Policy ' + policy.id + ' successfully edited'
        });
        //$rootScope.policiesCount++;
        self.loadData(self.curPage);
      };

      self.openEditPolicyDialog = function (policy) {
  
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/policies/policieslist/policy.edit.dialog.html',
          controller: EditPolicyController,
          controllerAs: '$ctrl',
          resolve: {
            policy: policy
          }
        });
        console.debug(modalInstance);
        modalInstance.result.then(self.handleEditPolicySuccess);
      };
      
    }

    angular
    .module('dashboardApp')
    .component(
      'policieslist',
      {
        require: {
          $parent: '^policies'
        },
        bindings: {
          policies: '<',
          total: '<'
        },
        templateUrl: '/resources/iam/apps/dashboard-app/components/policies/policieslist/policies.policieslist.component.html',
        controller: ['$q', '$scope', '$rootScope', '$uibModal', 'ModalService',
          'PoliciesService', 'toaster', "scimFactory", 'GroupsService', 'GroupRequestsService', PoliciesListController]
      });
})();