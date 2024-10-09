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

//// LIST FUNCTION

func listAdCustomRoles(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, _, err := GetGraphClient(ctx, d)

	if err != nil {
		plugin.Logger(ctx).Error("azuread_custom_role.listAdCustomRoles", "connection_error", err)
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
		plugin.Logger(ctx).Error("listAdCustomRoles", "list_custom_role_error", errObj)
		return nil, errObj
	}

	var ids []string //set of ids of all assumed roles in current directory
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
						errObj := getErrorObject(err)
						plugin.Logger(ctx).Error("listAdCustomRoles", "list_custom_role_error", errObj)
						return nil, errObj
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
		plugin.Logger(ctx).Error("azuread_custom_role.getAdCustomRole", "connection_error", err)
		return nil, err
	}

	customRole, err := client.RoleManagement().Directory().RoleDefinitions().ByUnifiedRoleDefinitionId(CustomRoleId).Get(ctx, nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("getCustomRole", "get_custom_error", errObj)
		return nil, errObj
	}

	members, err := getMembersFromId(ctx, d, CustomRoleId)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("getAdCustomRole", "get_custom_role_error", errObj)
		return nil, errObj
	}
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

// iterates over all role permission resources of the role and returns a list of json formating
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

// returns the role id from the UnifiedRoleDefinitionable struct
func getRoleId(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	return *data.role.GetId(), nil
}

// returns the role description (if exists) from the UnifiedRoleDefinitionable struct, "No Description" otherwise
func getRoleDescripsion(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	if data.role.GetDescription() == nil {
		return "No Description", nil
	}
	return *data.role.GetDescription(), nil
}

// returns the role display name from the UnifiedRoleDefinitionable struct
func getRoleDisplayName(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	return *data.role.GetDisplayName(), nil
}

// returns the role templateId from the UnifiedRoleDefinitionable struct
func getRoleTemplateId(_ context.Context, d *transform.TransformData) (interface{}, error) {
	data := d.HydrateItem.(*RoleDefinition)
	return *data.role.GetTemplateId(), nil
}

// returns the display name as the title, or the id if name doesn't exist
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

// returns a list of the ids of all principals who have this role assumed (not only directly by user)
func getMembersFromId(ctx context.Context, d *plugin.QueryData, id string) ([]string, error) {
	client, _, err := GetGraphClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_custom_role", "connection_error", err)
		return nil, err
	}
	var member_ids []string
	assignments, err := client.RoleManagement().Directory().RoleAssignments().Get(context.Background(), nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("azuread_custom_role", "list_custom_role_error", errObj)
		return nil, errObj
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
