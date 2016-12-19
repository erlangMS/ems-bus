"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var core_1 = require('@angular/core');
var platform_browser_1 = require('@angular/platform-browser');
var forms_1 = require("@angular/forms");
var http_1 = require('@angular/http');
var app_component_1 = require('./app.component');
var navigator_controller_1 = require('../modules/dashboard/controller/navigator_controller');
var sobre_1 = require('../modules/dashboard/controller/sobre');
var catalogo_controller_1 = require('../modules/catalogo/catalogo_controller');
var login_component_1 = require('../modules/login/login_component');
var angular2_datatable_1 = require('angular2-datatable');
//import {NgbModule} from '@ng-bootstrap/ng-bootstrap';
var AppModule = (function () {
    function AppModule() {
    }
    AppModule = __decorate([
        core_1.NgModule({
            imports: [
                platform_browser_1.BrowserModule,
                forms_1.FormsModule,
                http_1.HttpModule,
                angular2_datatable_1.DataTableModule],
            declarations: [app_component_1.AppComponent, navigator_controller_1.NavigatorController, sobre_1.Sobre, catalogo_controller_1.CatalogoController, login_component_1.LoginComponent],
            bootstrap: [app_component_1.AppComponent, navigator_controller_1.NavigatorController]
        }), 
        __metadata('design:paramtypes', [])
    ], AppModule);
    return AppModule;
}());
exports.AppModule = AppModule;
//# sourceMappingURL=app.module.js.map