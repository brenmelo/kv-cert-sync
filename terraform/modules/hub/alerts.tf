# Alerting. Created only when alert_email_addresses is not empty.
#
# Three independent signals, so one failing component cannot hide the others:
#   1. failures  - the functions logged a permanent failure, a transient failure or a blocked renewal
#   2. heartbeat - a function app stopped running its timer sweep (it logs "reconcile-complete" every sweep)
#   3. replica   - the copy that applications use is close to expiry although it is up to date. This is the end-to-end check:
#                  whatever went wrong upstream (renewal, the CA, the tag, the copy), the certificate is going stale.
#                  The sync function reports it ("KVSYNC result=replica-expiring", threshold REPLICA_WARN_DAYS, default 7)
#                  because Key Vault's own near-expiry event is fixed at 30 days before expiry: with a 47-day certificate
#                  that is two weeks BEFORE a healthy renewal, so an alert on that event would fire for every certificate.
#
# Every rule is STATEFUL (auto_mitigation_enabled): one notification when it fires and one when the condition clears,
# instead of one e-mail per evaluation for as long as the problem lasts.

locals {
  alerts_enabled = length(var.alert_email_addresses) > 0
  app_log_prefix = { sync = "KVSYNC", renew = "KVRENEW" }
}

resource "azurerm_monitor_action_group" "ops" {
  count               = local.alerts_enabled ? 1 : 0
  name                = "ag-kvsync-${var.suffix}"
  short_name          = "kvsync"
  resource_group_name = var.resource_group_name
  tags                = local.tags

  dynamic "email_receiver" {
    for_each = { for i, e in var.alert_email_addresses : tostring(i) => e }
    content {
      name                    = "receiver-${email_receiver.key}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "failures" {
  count                   = local.alerts_enabled ? 1 : 0
  name                    = "alert-kvsync-failures-${var.suffix}"
  display_name            = "Key Vault certificate sync/renew: failure"
  description             = "A KVSYNC or KVRENEW line reports a failed copy, a failed renewal, or a renewal blocked by the rate limit."
  location                = var.location
  resource_group_name     = var.resource_group_name
  scopes                  = [azurerm_log_analytics_workspace.this.id]
  severity                = 2
  evaluation_frequency    = "PT5M"
  window_duration         = "PT15M"
  auto_mitigation_enabled = true
  tags                    = local.tags

  criteria {
    query                   = <<-KQL
      AppTraces
      | where Message contains "KVSYNC result=failed" or Message contains "KVRENEW result=failed" or Message contains "KVRENEW result=blocked"
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThanOrEqual"
    threshold               = 1

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.ops[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "heartbeat" {
  for_each                = local.alerts_enabled ? local.apps : {}
  name                    = "alert-${each.value.label}-heartbeat-${var.suffix}"
  display_name            = "Key Vault certificate ${each.key}: no sweep in the last hour"
  description             = "The ${each.key} function app has not logged a completed timer sweep. The app is stopped, throttled, or cannot start."
  location                = var.location
  resource_group_name     = var.resource_group_name
  scopes                  = [azurerm_log_analytics_workspace.this.id]
  severity                = 2
  evaluation_frequency    = "PT15M"
  window_duration         = "PT1H"
  auto_mitigation_enabled = true
  tags                    = local.tags

  criteria {
    query                   = <<-KQL
      AppTraces
      | where Message contains "${local.app_log_prefix[each.key]} result=reconcile-complete"
    KQL
    time_aggregation_method = "Count"
    operator                = "LessThan"
    threshold               = 1

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.ops[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "replica_expiring" {
  count                   = local.alerts_enabled && length(local.dest) > 0 ? 1 : 0
  name                    = "alert-kvsync-replica-expiring-${var.suffix}"
  display_name            = "Key Vault certificate sync: a copy is about to expire"
  description             = "A certificate copy has fewer days left than REPLICA_WARN_DAYS (default 7), although the sync is up to date. A healthy chain renews and copies long before that, so renewal, the CA or the source tag is stuck."
  location                = var.location
  resource_group_name     = var.resource_group_name
  scopes                  = [azurerm_log_analytics_workspace.this.id]
  severity                = 1
  evaluation_frequency    = "PT15M"
  window_duration         = "PT1H"
  auto_mitigation_enabled = true
  tags                    = local.tags

  criteria {
    query                   = <<-KQL
      AppTraces
      | where Message contains "KVSYNC result=replica-expiring"
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThanOrEqual"
    threshold               = 1

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.ops[0].id]
  }
}
