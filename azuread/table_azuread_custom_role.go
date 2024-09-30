package azuread

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableAzureAdCustomRole(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azuread_custom_role",
		Description: "Represents all assigned custom roles in azure Active Directory",
		Get: &plugin.GetConfig{
			Hydrate: getAdCustomRole,
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isIgnorableErrorPredicate([]string{"Request_ResourceNotFound", "Invalid object identifier"}),
			},
			KeyColumns: plugin.SingleColumn("id"),
		},
		List: &plugin.ListConfig{
			Hydrate: listAdCustomRoles,
		},
		Columns: commonColumns([]*plugin.Column{
			{Name: "id", Type: proto.ColumnType_STRING, Description: "The unique identifier for the role.", Transform: transform.From(getRoleId)},
			{Name: "description", Type: proto.ColumnType_STRING, Description: "The description for the role.", Transform: transform.From(getRoleDescripsion)},
			{Name: "display_name", Type: proto.ColumnType_STRING, Description: "The display name for the role.", Transform: transform.From(getRoleDisplayName)},

			// Other fields
			{Name: "role_template_id", Type: proto.ColumnType_STRING, Transform: transform.From(getRoleTemplateId), Description: "The id of the directoryRoleTemplate that this role is based on. The property must be specified when activating a directory role in a tenant with a POST operation. After the directory role has been activated, the property is read only."},

			// Json fields
			{Name: "member_ids", Type: proto.ColumnType_JSON, Transform: transform.From(getCustomRoleMembers), Description: "Id of the owners of the application. The owners are a set of non-admin users who are allowed to modify this object."},

			{Name: "role_premissions", Type: proto.ColumnType_JSON, Transform: transform.From(getRolePermissions), Description: "Permissions of the custom role"},

			// Standard columns
			{Name: "title", Type: proto.ColumnType_STRING, Description: ColumnDescriptionTitle, Transform: transform.From(getCustomRoleTitle)},
		}),
	}
}

type RoleDefinition struct {
	role    models.UnifiedRoleDefinitionable
	members []string
}

type RolePermissions struct {
	models.UnifiedRolePermission
}

//// LIST FUNCTION

func listAdCustomRoles(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, _, err := GetGraphClient(ctx, d)

	if err != nil {
		plugin.Logger(ctx).Error("azuread_custom_role.listAdCustomRoles", "connection_error", err) //TODO: fix
		return nil, err
	}

	result, err := client.RoleManagement().Directory().RoleDefinitions().Get(context.Background(), nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("listAdCustomRoles", "list_custom_role_error", errObj)
		return nil, errObj
	}

	roleAssignments, err := client.RoleManagement().Directory().RoleAssignments().Get(context.Background(), nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("listAdCustomRoles", "list_custom_role_error", errObj) //potentialy change
		return nil, errObj
	}

	var ids []string
	for _, assignment := range roleAssignments.GetValue() {
		found := false
		for _, id := range ids {
			if id == *assignment.GetRoleDefinitionId() {
				found = true
			}
		}
		if !found {
			ids = append(ids, *assignment.GetRoleDefinitionId())
		}
	}

	for _, customRole := range result.GetValue() {

		if !*customRole.GetIsBuiltIn() {
			for _, id := range ids {
				if id == *customRole.GetTemplateId() {
					members, err := getMembersFromId(ctx, d, id)
					if err != nil {
						//todo: add error log
					}
					d.StreamListItem(ctx, &RoleDefinition{customRole, members})
				}
			}
		}

		// Context can be cancelled due to manual cancellation or the limit has been hit
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getAdCustomRole(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	CustomRoleId := d.EqualsQuals["id"].GetStringValue()
	if CustomRoleId == "" {
		return nil, nil
	}

	// Create client
	client, _, err := GetGraphClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_directory_role.getAdDirectoryRole", "connection_error", err) //fix
		return nil, err
	}

	customRole, err := client.RoleManagement().Directory().RoleDefinitions().ByUnifiedRoleDefinitionId(CustomRoleId).Get(ctx, nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("getAdDirectoryRole", "get_directory_role_error", errObj) //fix
		return nil, errObj
	}

	members, err := getMembersFromId(ctx, d, CustomRoleId)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("getAdCustomRole", "get_custom_role_error", errObj)
		return nil, errObj
	}
	//todo: add error log
	return &RoleDefinition{customRole, members}, nil
}

func getCustomRoleMembers(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	if data == nil {
		return nil, nil
	}
	return data.members, nil

}

//// TRANSFORM FUNCTIONS

// iterates over all role permission resources of the role
func getRolePermissions(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	permissionArray := data.role.GetRolePermissions()
	resourceArr := []map[string]interface{}{}
	for _, per := range permissionArray {
		mapping := map[string]interface{}{}
		allowedResourceActionsArr := per.GetAllowedResourceActions()
		if allowedResourceActionsArr == nil {
			mapping["AllowedResourceActions"] = []string{}
		} else {
			mapping["AllowedResourceActions"] = per.GetAllowedResourceActions()
		}
		excludedResourceActionsArr := per.GetExcludedResourceActions()
		if excludedResourceActionsArr == nil {
			mapping["ExcludedResourceActions"] = []string{}
		} else {
			mapping["ExcludedResourceActions"] = per.GetExcludedResourceActions()
		}
		mapping["condition"] = per.GetCondition()
		resourceArr = append(resourceArr, mapping)
	}
	return resourceArr, nil
}

func getRoleId(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	return *data.role.GetId(), nil
}

func getRoleDescripsion(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	if data.role.GetDescription() == nil {
		return "No Description", nil
	}
	return *data.role.GetDescription(), nil
}

func getRoleDisplayName(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	return *data.role.GetDisplayName(), nil
}

func getRoleTemplateId(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	return *data.role.GetTemplateId(), nil
}

func getCustomRoleTitle(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	if data == nil {
		return nil, nil
	}

	title := data.role.GetDisplayName()
	if title == nil {
		title = data.role.GetId()
	}

	return title, nil
}

//// HELPER FUNCTIONS

func getMembersFromId(ctx context.Context, d *plugin.QueryData, id string) ([]string, error) {
	client, _, err := GetGraphClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_custom_role.listAdCustomRoles", "connection_error", err) //TODO: fix
		return nil, err
	}
	var member_ids []string
	assignments, err := client.RoleManagement().Directory().RoleAssignments().Get(context.Background(), nil)
	if err != nil {
		//todo" fix
	}
	for _, assignment := range assignments.GetValue() {
		newId := *assignment.GetRoleDefinitionId()
		principalId := *assignment.GetPrincipalId()
		if newId == id {
			found := false
			for _, id := range member_ids {
				if id == principalId {
					found = true
				}
			}
			if !found {
				member_ids = append(member_ids, principalId)
			}
		}
	}
	return member_ids, nil
}
