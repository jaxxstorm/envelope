resource "aws_cloudwatch_metric_alarm" "instance_status" {
  for_each = aws_instance.controller

  alarm_name          = "${var.name}-${each.key}-instance-status"
  alarm_description   = "Standalone controller EC2 instance or system status check failed"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  dimensions          = { InstanceId = each.value.id }
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  treat_missing_data  = "breaching"
  alarm_actions       = sort(tolist(var.alarm_actions))
  ok_actions          = sort(tolist(var.alarm_actions))

  tags = merge(local.common_tags, {
    Role         = "controller-alarm"
    ControllerID = each.key
  })
}

locals {
  dynamodb_throttle_metrics = {
    read_throttles  = "ReadThrottleEvents"
    write_throttles = "WriteThrottleEvents"
  }
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_throttles" {
  for_each = local.dynamodb_throttle_metrics

  alarm_name          = "${var.name}-dynamodb-${each.key}"
  alarm_description   = "Controller authority DynamoDB ${each.value} is nonzero"
  namespace           = "AWS/DynamoDB"
  metric_name         = each.value
  dimensions          = { TableName = aws_dynamodb_table.authority.name }
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = sort(tolist(var.alarm_actions))
  ok_actions          = sort(tolist(var.alarm_actions))

  tags = merge(local.common_tags, {
    Role = "controller-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_system_errors" {
  alarm_name          = "${var.name}-dynamodb-system-errors"
  alarm_description   = "Controller authority DynamoDB system errors are nonzero"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = sort(tolist(var.alarm_actions))
  ok_actions          = sort(tolist(var.alarm_actions))

  metric_query {
    id          = "get_item_errors"
    return_data = false

    metric {
      namespace   = "AWS/DynamoDB"
      metric_name = "SystemErrors"
      dimensions = {
        TableName = aws_dynamodb_table.authority.name
        Operation = "GetItem"
      }
      period = 60
      stat   = "Sum"
    }
  }

  metric_query {
    id          = "put_item_errors"
    return_data = false

    metric {
      namespace   = "AWS/DynamoDB"
      metric_name = "SystemErrors"
      dimensions = {
        TableName = aws_dynamodb_table.authority.name
        Operation = "PutItem"
      }
      period = 60
      stat   = "Sum"
    }
  }

  metric_query {
    id          = "total_errors"
    expression  = "get_item_errors + put_item_errors"
    label       = "Controller DynamoDB system errors"
    return_data = true
  }

  tags = merge(local.common_tags, {
    Role = "controller-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "controller_ready" {
  for_each = var.controller_placements

  alarm_name        = "${var.name}-${each.key}-ready"
  alarm_description = "External collector did not report this standalone controller ready"
  namespace         = var.controller_ready_metric.namespace
  metric_name       = var.controller_ready_metric.metric_name
  dimensions = {
    ControllerId = each.key
    DeploymentId = var.name
    PublisherId  = var.readiness_publisher.id
  }
  statistic           = "Minimum"
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = var.controller_ready_metric.period_seconds
  evaluation_periods  = var.controller_ready_metric.evaluation_periods
  datapoints_to_alarm = var.controller_ready_metric.evaluation_periods
  treat_missing_data  = "breaching"
  alarm_actions       = sort(tolist(var.alarm_actions))
  ok_actions          = sort(tolist(var.alarm_actions))

  tags = merge(local.common_tags, {
    Role         = "controller-alarm"
    ControllerID = each.key
  })
}
