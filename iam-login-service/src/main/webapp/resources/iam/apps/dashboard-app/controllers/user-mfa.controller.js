/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
  'use strict';

  angular.module('dashboardApp')
      .controller('UserMfaController', UserMfaController);

  UserMfaController.$inject = [
    '$scope', '$state', '$uibModalInstance', 'Utils', 'user'
  ];

  function UserMfaController(
      $scope, $state, $uibModalInstance, Utils, user) {
    var userMfaCtrl = this;

    userMfaCtrl.$onInit = function() {
      console.log('UserMfaController onInit');
    };

    userMfaCtrl.userToEdit = user;
    
    userMfaCtrl.authenticatorAppActive = true;
    userMfaCtrl.enableAuthenticatorApp = enableAuthenticatorApp;
    userMfaCtrl.disableAuthenticatorApp = disableAuthenticatorApp;
    userMfaCtrl.enableYubiKey = enableYubiKey;
    userMfaCtrl.disableYubiKey = disableYubiKey;

    function enableAuthenticatorApp() {
      return true;
    }

    function disableAuthenticatorApp() {
      return true;
    }

    function enableYubiKey() {
      return true;
    }

    function disableYubiKey() {
      return true;
    }

    userMfaCtrl.dismiss = dismiss;
    userMfaCtrl.reset = reset;

    function reset() {
      console.log('reset form');

      userMfaCtrl.enabled = true;

      userMfaCtrl.user = {
        currentPassword: '',
        password: '',
        confirmPassword: ''
      };

      if ($scope.userMfaForm) {
        $scope.userMfaForm.$setPristine();
      }
    }

    userMfaCtrl.reset();

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    userMfaCtrl.message = '';

    userMfaCtrl.submit = function() {
      return $uibModalInstance.close('Updated settings');
      // ResetPasswordService
      //     .updatePassword(
      //         userMfaCtrl.user.currentPassword,
      //         userMfaCtrl.user.password)
      //     .then(function() { return $uibModalInstance.close('Password updated'); })
      //     .catch(function(error) {
      //       console.error(error);
      //       $scope.operationResult = Utils.buildErrorResult(error.data);
      //     });
    };
  }

//   var compareTo = function() {
//     return {
//       require: 'ngModel',
//       scope: {otherModelValue: '=compareTo'},
//       link: function(scope, element, attributes, ngModel) {

//         ngModel.$validators.compareTo = function(modelValue) {
//           return modelValue == scope.otherModelValue;
//         };

//         scope.$watch('otherModelValue', function() { ngModel.$validate(); });
//       }
//     };
//   };

//   angular.module('dashboardApp').directive('compareTo', compareTo);
// })();