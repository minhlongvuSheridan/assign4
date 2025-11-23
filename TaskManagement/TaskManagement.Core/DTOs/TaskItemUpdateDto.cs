using System.ComponentModel.DataAnnotations;
namespace TaskManagement.Core.DTOs;

public class TaskItemUpdateDto
{
    [Required(ErrorMessage = "Title is required")]
    [StringLength(200, ErrorMessage = "Title cannot exceed 200 characters")]
    public string Title { get; set; } = string.Empty;
    [StringLength(1000, ErrorMessage = "Description cannot exceed 1000 characters")]
    public string? Description { get; set; }

    [Required]
    public Models.TaskStatus Status { get; set; }
    public DateTime? DueDate { get; set; }
}